from setuptools import find_packages, setup

setup(
    name='pcredz-ultimate',
    version='3.1.0',
    description='Passive credential and authentication-material auditing for authorized network captures',
    packages=find_packages(),
    python_requires='>=3.10',
    entry_points={'console_scripts': [
        'pcredz=pcredz_ultimate.cli:main',
        'pcredz-ultimate=pcredz_ultimate.cli:main',
    ]},
)
