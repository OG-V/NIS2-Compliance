"""Product adapters: read one product's API and describe it in a product-neutral model.

Each category (identity, ...) defines the evidence its checks need, independent of
any product. An adapter per product fetches the product's raw data and normalises
it into that model. Checks read only the neutral model, so they work for every
product the category supports.
"""
