FROM grahamdumpleton/mod-wsgi-docker:python-2.7-onbuild
CMD ["python", "migrate.py"]
CMD [ "app.wsgi" ]
