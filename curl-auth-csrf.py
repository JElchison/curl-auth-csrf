#!/usr/bin/env python

import logging
import sys
import argparse
import urlparse
import os
import requests
import lxml.html


VERSION = '0.1.0'


logging.basicConfig(level=logging.DEBUG)


def parse_arguments():
    parser = argparse.ArgumentParser(prog='curl-auth-csrf.py', description='Python tool that mimics curl, but performs a login and handles any Cross-Site Request Forgery (CSRF) tokens', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a', '--user-agent-str', help='User-Agent string to use', default='Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36')

    parser.add_argument('-i', '--login-url', required=True, help='URL that contains the login form')
    parser.add_argument('-j', '--logout-url', help='URL to be visited to perform the logout')

    parser.add_argument('-f', '--form-id', help='HTML id attribute of login form')
    parser.add_argument('-p', '--password-field-name', help='name of input field containing password')
    parser.add_argument('-d', '--data', metavar='DATA', help='adds the specified data to the form submission (usually just the username)')

    parser.add_argument('-u', '--success-url', help='URL substring constituting successful login')
    parser.add_argument('-t', '--success-text', help='HTML snippet constituting successful login')

    parser.add_argument('-o', '--output', metavar='FILE', type=argparse.FileType('w'), default=sys.stdout, help='write output to <file> instead of stdout')

    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('url_after_login', nargs='+')

    # TODO add example
    parser.epilog = "Actual password should be passed in via stdin.\n\nExample flow:\n\t"

    return parser


def perform_login(args, password):
    session = requests.session()

    logging.info('Performing GET on login URL ...')
    result = session.get(args.login_url, verify=False, headers={'User-Agent': args.user_agent_str})
    logging.info("Request result = %d", result.status_code)
    result.raise_for_status()

    logging.debug('Parsing result from login request ...')
    tree = lxml.html.fromstring(result.text)

    login_form = None
    if args.form_id:
        logging.debug('Login form id field specified at command line')
        try:
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
    logging.info('Identified login form as ' + lxml.html.tostring(login_form))

    if args.password_field_name:
        logging.debug('Password field specified at command line')
        password_field_name = args.password_field_name
    else:
        logging.debug('No password field specified at command line.  Identifying dynamically...')
        password_field = list(set(login_form.xpath(".//input[@type='password']")))[0]
        password_field_name = password_field.name
    logging.info('Using password_field_name = ' + password_field_name)

    logging.debug('Initializing data dictionary ...')
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
        if not input_field.name:
            logging.debug("\tNo 'name' attribute.  Continuing...")
            continue
        if input_field.name in data:
            logging.debug("\tField overlaps with provided data.  Continuing...")
            continue

        logging.info("Adding carry-over data %s to dictionary ..." % input_field)
        if input_field.name not in data:
            data[input_field.name] = []
        data[input_field.name].append(input_field.value)

    logging.debug('Dictionary = %s', data)

    logging.debug('Parsing response URL ...')
    if "://" not in login_form.action:
        url_parts = urlparse.urlparse(result.url)
        next_url = "%s://%s%s/%s" % (url_parts.scheme, url_parts.netloc, os.path.dirname(url_parts.path), login_form.action)
    else:
        next_url = login_form.action
    logging.info("Calculated next_url = " + next_url)

    if login_form.method == "get":
        logging.info('Performing GET on form submission ...')
        result = session.get(next_url, data, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
    else:
        logging.info('Performing POST on form submission ...')
        result = session.post(next_url, data, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
    logging.info("Request result = %d", result.status_code)
    logging.info('Result URL after login = %s' % result.url)
    result.raise_for_status()

    if args.success_url and args.success_url not in result.url:
        logging.info("content = " + result.content)
        raise Exception("Specified success_url '%s' not in result URL '%s'.  Failed to login?" % (args.success_url, result.url))
    if args.success_text and args.success_text not in result.content:
        logging.info("content = " + result.content)
        raise Exception("Specified success_text not in result content.  Failed to login?")

    logging.debug('Making requests of interest ...')
    for url_after_login in args.url_after_login:
        logging.info('Performing GET on %s ...' % url_after_login)
        result = session.get(url_after_login, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
        logging.info("Request result = %d", result.status_code)
        args.output.write(result.content)

    if args.logout_url:
        logging.info('Performing GET on logout ...')
        result = session.get(args.logout_url, verify=False, headers={'Referer': result.url, 'User-Agent': args.user_agent_str})
        logging.info("Request result = %d", result.status_code)


def main():
    logging.debug('Setting up argument parser ...')
    parser = parse_arguments()
    logging.debug('Parsing command line arguments ...')
    args = parser.parse_args()

    logging.debug('Reading password from stdin ...')
    password = sys.stdin.read()

    perform_login(args, password)


if __name__ == "__main__":
    main()
