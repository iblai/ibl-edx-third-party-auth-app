import os
from setuptools import setup, find_packages
from glob import glob
from os.path import basename, splitext


def package_data(pkg, roots):
    """Generic function to find package_data.

    All of the files under each of the `roots` will be declared as package
    data for package `pkg`.

    """
    data = []
    for root in roots:
        for dirname, _, files in os.walk(os.path.join(pkg, root)):
            for fname in files:
                data.append(os.path.relpath(os.path.join(dirname, fname), pkg))

    return {pkg: data}


setup(
    name='ibl-third-party-auth',
    version='2.0.0',
    install_requires=[
        "ddt",
        "social-auth-app-django",
        "httpretty",
        "freezegun",
        "testfixtures",
        "python3-saml"
    ],
    description='EdX Third Parth Auth package with IBL specific modifications',
    license='UNKNOWN',       # TODO: choose a license: 'AGPL v3' and 'Apache 2.0' are popular.
    packages=find_packages("src"),
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    entry_points={
        'lms.djangoapp': [
            'ibl_third_party_auth = ibl_third_party_auth.apps:IBLThirdPartyAuthConfig',
        ],
        'cms.djangoapp': [
            'ibl_third_party_auth = ibl_third_party_auth.apps:IBLThirdPartyAuthConfig',
        ],

    },
    package_data=package_data("ibl_third_party_auth", ["api", "patches", "settings"]),
)
