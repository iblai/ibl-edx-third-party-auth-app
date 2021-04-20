import os
from setuptools import setup, find_packages


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
    name='third_party_auth',
    version='1.1.1',
    description='EdX Third Parth Auth package with IBL specific modifications',
    license='UNKNOWN',       # TODO: choose a license: 'AGPL v3' and 'Apache 2.0' are popular.
    packages=find_packages(),
    package_data=package_data("third_party_auth", ["api", "management", "migrations", "templates"]),
)
