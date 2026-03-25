from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.name


class AdvancedSearch(models.Model):
    name = models.CharField(max_length=64, null=False, blank=False)
    query = models.TextField(max_length=1000, null=False, blank=False)
    categories = models.ManyToManyField(Category, blank=True)

    def __str__(self):
        return self.query
