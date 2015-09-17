from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='server_cookie_middleware',
      version=version,
      description="",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Quintagroup',
      author_email='',
      url='',
      license='Apache License 2.0',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
          'oslo.middleware',
          'pycrypto',
          'pytz',
          'webob',
      ],
      entry_points="""
      # -*- Entry points: -*-
      [paste.filter_app_factory]
      server_cookie_middleware = server_cookie_middleware.middleware:ServerCookieMiddleware.factory
      """,
      )
