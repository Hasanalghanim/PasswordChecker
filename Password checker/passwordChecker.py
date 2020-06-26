import requests
import hashlib
import sys


# Gets API from PWNEDPASSWORDS
def request_api_data(query_cher):
    url = "https://api.pwnedpasswords.com/range/" + query_cher
    res = requests.get(url)

    # Forced ERROR if API not accepted (400)
    if res.status_code != 200:
        raise RuntimeError(
            f"error fetching: {res.status_code}, check api and try again")
    return res


def get_leaks(hashes, has_to_check):
    # splits the Hash text
    hashes = (line.split(":") for line in hashes.text.splitlines())
    # Checks the times the Hash text comes up
    for h, count in hashes:
        if h == has_to_check:
            return count
    return 0


def pwned_checker(password):
    # Encodes to Sha1 & makes uppercase.
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    # Splits first 5 and last.
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_checker(password)
        if count:
            print(f"'{password}' was found {count} times.... you should change it!")
        else:
            print(
                f"The password '{password}' was not found, continue with that password.")
    return "done"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


# To RUN passwordChecker on Term/CD... input /// path/to/file>"python passwordChecker.py *password*
