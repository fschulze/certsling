from setuptools import setup


setup(
    name='gentlskey',
    install_requires=[
        'click',
        'pyOpenSSL',
        'requests'],
    entry_points={
        'console_scripts': ['gentlskey = gentlskey:main']},
    pyackages=['gentlskey'])
