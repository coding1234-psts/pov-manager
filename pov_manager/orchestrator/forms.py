from django import forms
from .models import AdvancedSearch, Category


class AdvancedSearchForm(forms.ModelForm):
    class Meta:
        model = AdvancedSearch
        fields = ['name', 'query', 'categories']


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name']