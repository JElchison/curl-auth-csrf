#!/usr/bin/env python

# curl-auth-csrf.py
#
# Python tool that mimics cURL, but performs a login and handles any Cross-Site Request Forgery (CSRF) tokens.  Useful for scraping HTML normally only accessible when logged in.
#
# Copyright (C) 2016 Jonathan Elchison <JElchison@gmail.com>


import logging
import sys
import argparse
import urlparse
import os
import requests
import lxml.html


VERSION = '1.0.0'


logging.basicConfig(level=logging.WARNING)


def parse_arguments():
    parser = argparse.ArgumentParser(prog='curl-auth-csrf.py', description='Python tool that mimics curl, but performs a login and handles any Cross-Site Request Forgery (CSRF) tokens', formatter_class=argparse.RawDescriptionHelpFormatter)

    # NOTE: keep this default something common and benign
    parser.add_argument('-a', '--user-agent-str', help='User-Agent string to use',
                        default='Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36')

    parser.add_argument('-i', '--login-url', required=True, help='URL that contains the login form')

    parser.add_argument('-f', '--form-id', help='HTML id attribute of login form')
    parser.add_argument('-p', '--password-field-name', help='name of input field containing password')
    parser.add_argument('-d', '--data', metavar='DATA', help='adds the specified data to the form submission (usually just the username)')

    parser.add_argument('-u', '--success-url', help='URL substring constituting successful login')
    parser.add_argument('-t', '--success-text', help='HTML snippet constituting successful login')

    parser.add_argument('-j', '--logout-url', help='URL to be visited to perform the logout')

    parser.add_argument('-o', '--output', metavar='FILE', type=argparse.FileType('w'), default=sys.stdout, help='write output to <file> instead of stdout')

    parser.add_argument('url_after_login', nargs='+')

    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)

    parser.epilog = "Actual password should be passed in via stdin.\n\nSee README for examples."

    return parser


def identify_login_form(args, result):
    tree = lxml.html.fromstring(result.text)

    login_form = None
    if args.form_id:
        logging.debug('Login form id field specified at command line')
        try:
            # take the first occurrence if there are multiple with this id
            login_form = list(set(tree.xpath("//form[@id='%s']" % args.form_id)))[0]
        except IndexError:
            logging.warning("Login form id '%s' not found.  Identifying dynamically..." % args.form_id)
    else:
        logging.debug('No login form id field specified at command line.  Identifying dynamically...')

    if login_form is None:
        login_forms = list(set(tree.xpath("//form//input[@type='password']/ancestor::form")))
        if len(login_forms) != 1:
            raise Exception("Cannot identify login form dynamically.  Try again with '-f'.")
        login_form = login_forms[0]

    logging.debug('Identified login form as ' + lxml.html.tostring(login_form))
    return login_form


def identify_password_field_name(args, login_form):
    if args.password_field_name:
        logging.debug('Password field specified at command line')
        password_field_name = args.password_field_name
    else:
        logging.debug('No password field specified at command line.  Identifying dynamically...')
        password_field = list(set(login_form.xpath(".//input[@type='password']")))[0]
        password_field_name = password_field.name

    logging.info('Identified password field name as ' + password_field_name)
    return password_field_name


def setup_data_dictionary(args, login_form, password_field_name, password):
    data = {}
    if args.data:
        logging.debug('Adding specified data to dictionary ...')
        data = urlparse.parse_qs(args.data)

    logging.debug('Adding password to dictionary ...')
    if password_field_name not in data:
        data[password_field_name] = []
    data[password_field_name].append(password)

    logging.debug('Parsing input fields in login form ...')
    input_fields = list(set(login_form.xpath(".//input")))
    for input_field in input_fields:
        logging.debug("Parsing %s ..." % input_field)
        # items without names can't appear in a query string
        if not input_field.name:
            logging.debug("\tNo 'name' attribute.  Continuing...")
            continue
        # don't overwrite (things like real username and password)
        if input_field.name in data:
            logging.debug("\tField overlaps with provided data.  Continuing...")
            continue

        logging.debug("Adding carry-over data %s to dictionary ..." % input_field)
        if input_field.name not in data:
            data[input_field.name] = []
        data[input_field.name].append(input_field.value)

    logging.debug('Data dictionary = %s', data)
    return data


def calculate_action_url(login_form, result):
    if "://" not in login_form.action:
        url_parts = urlparse.urlparse(result.url)
        action_url = "%s://%s%s/%s" % (url_parts.scheme, url_parts.netloc, os.path.dirname(url_parts.path), login_form.action)
    else:
        action_url = login_form.action

    logging.info("Calculated action_url as " + action_url)
    return action_url


def verify_login_success(args, result):
    if args.success_url and args.success_url not in result.url:
        logging.debug("content = " + result.content)
        raise Exception("Specified success_url '%s' not in result URL '%s'.  Failed to login?" % (args.success_url, result.url))
    if args.success_text and args.success_text not in result.content:
        logging.debug("content = " + result.content)
        raise Exception("Specified success_text not in result content.  Failed to login?")

    logging.info("Login was successful")


def main():
    logging.debug('Setting up argument parser ...')
    parser = parse_arguments()
    logging.debug('Parsing command line arguments ...')
    args = parser.parse_args()

    logging.debug('Reading password from stdin ...')
    password = sys.stdin.read()

    logging.debug('Allocating session ...')
    session = requests.session()

    #################
    # get login page
    #################

    logging.info('Performing GET on login URL ...')
    result = session.get(args.login_url, verify=False, headers={'User-Agent': args.user_agent_str})
    logging.info("Request result = %d", result.status_code)
    result.raise_for_status()

    ###################
    # parse login page
    ###################

    logging.debug('Parsing login page ...')
    login_form = identify_login_form(args, result)
    password_field_name = identify_password_field_name(args, login_form)
    logging.debug('Initializing data dictionary ...')
    data = setup_data_dictionary(args, login_form, password_field_name, password)
    logging.debug('Calculating action URL ...')
    action_url = calculate_action_url(login_form, result)

    ####################
    # submit login form
    ####################

    if login_form.method == "get":
        logging.info('Performing GET on form submission ...')
        result = session.get(action_url, data, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
    else:
        logging.info('Performing POST on form submission ...')
        result = session.post(action_url, data, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
    logging.info("Request result = %d", result.status_code)
    logging.info('Result URL after login = %s' % result.url)
    result.raise_for_status()

    verify_login_success(args, result)

    ############################
    # make requests of interest
    ############################

    logging.info('Making requests of interest ...')
    for url_after_login in args.url_after_login:
        logging.info('Performing GET on %s ...' % url_after_login)
        result = session.get(url_after_login, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
        logging.info("Request result = %d", result.status_code)
        args.output.write(result.content)

    #########
    # logout
    #########

    if args.logout_url:
        logging.info('Performing GET on logout URL ...')
        result = session.get(args.logout_url, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
        logging.info("Request result = %d", result.status_code)


if __name__ == "__main__":
    main()
