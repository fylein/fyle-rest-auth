"""
Project setup file
"""
import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='fyle-rest-auth',
    version='1.7.0',
    author='Shwetabh Kumar',
    author_email='shwetabh.kumar@fyle.in',
    description='Django application to implement OAuth 2.0 using Fyle in Django rest framework',
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords=['fyle', 'rest', 'django-rest-framework', 'api', 'python', 'oauth 2'],
    url='https://github.com/fylein/fyle-rest-auth',
    packages=setuptools.find_packages(),
    install_requires=['requests>=2.25.0', 'django>=3.0.2',
                      'django-rest-framework==0.1.0'],
    include_package_data=True,
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ]
)
