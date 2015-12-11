from setuptools import setup


setup(
    name='gentlskey',
    entry_points={
        'console_scripts': ['gentlskey = gentlskey:main']},
    pyackages=['gentlskey'])
