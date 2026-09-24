"""Evidence collectors: read config, probe services, gather raw evidence.

Each module registers its collectors with the @collector decorator;
registry.load_all() imports every module here.
"""
