from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import (
    CreateView,
    DetailView,
    ListView,
    TemplateView,
    UpdateView,
    DeleteView
)
from .models import (AdvancedSearch,
                     Category)
from .forms import (AdvancedSearchForm,
                    CategoryForm)


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'orchestrator/dashboard.html'


class AdvancedSearchListView(LoginRequiredMixin, ListView):
    model = AdvancedSearch
    template_name = 'orchestrator/advancedsearch_list.html'


class AdvancedSearchCreateView(LoginRequiredMixin, CreateView):
    model = AdvancedSearch
    form_class = AdvancedSearchForm
    template_name = 'orchestrator/advancedsearch_form.html'
    success_url = reverse_lazy('advancedsearch_list')


class AdvancedSearchUpdateView(LoginRequiredMixin, UpdateView):
    model = AdvancedSearch
    form_class = AdvancedSearchForm
    template_name = 'orchestrator/advancedsearch_form.html'
    success_url = reverse_lazy('advancedsearch_list')


class AdvancedSearchDeleteView(LoginRequiredMixin, DeleteView):
    model = AdvancedSearch
    template_name = 'orchestrator/advancedsearch_confirm_delete.html'
    success_url = reverse_lazy('advancedsearch_list')


class CategoryListView(LoginRequiredMixin, ListView):
    model = Category
    template_name = 'orchestrator/category_list.html'


class CategoryCreateView(LoginRequiredMixin, CreateView):
    model = Category
    form_class = CategoryForm
    template_name = 'orchestrator/category_form.html'
    success_url = reverse_lazy('category_list')


class CategoryUpdateView(LoginRequiredMixin, UpdateView):
    model = Category
    form_class = CategoryForm
    template_name = 'orchestrator/category_form.html'
    success_url = reverse_lazy('category_list')


class CategoryDeleteView(LoginRequiredMixin, DeleteView):
    model = Category
    template_name = 'orchestrator/category_confirm_delete.html'
    success_url = reverse_lazy('category_list')
