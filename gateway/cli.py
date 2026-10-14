import argparse
import getpass
from .config import load_config
from .db import DB


def main():
    cli = argparse.ArgumentParser(description='Manage the universal auth gateway')
    sub = cli.add_subparsers(dest='command', required=True)
    user = sub.add_parser('create-user', help='Create an account (private deployment owner)')
    user.add_argument('--email', required=True)
    user.add_argument('--password-stdin', action='store_true')
    client = sub.add_parser('register-client', help='Register an OAuth2 client')
    client.add_argument('--name', required=True)
    client.add_argument('--redirect-uri', action='append', required=True)
    client.add_argument('--kind', choices=['public','confidential'], required=True)
    client.add_argument('--origin', action='append', default=[], help='Permitted cross-origin token requests')
    client.add_argument('--scopes', nargs='+', default=['profile'])
    args = cli.parse_args()
    db = DB(load_config().database)
    if args.command == 'create-user':
        password = __import__('sys').stdin.readline().rstrip('\n') if args.password_stdin else getpass.getpass('Password (12+ characters): ')
        db.add_user(args.email, password)
        print('Account created:', args.email)
    if args.command == 'register-client':
        client_id, secret = db.add_client(args.name, args.redirect_uri, args.kind, args.scopes, args.origin)
        print('Client ID:', client_id)
        if secret:
            print('Client secret (save now, it is not stored in plain text):',secret)
        print('Allowed scopes:', ' '.join(args.scopes))

if __name__ == '__main__':
    main()
