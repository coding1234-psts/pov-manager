from .views import (
    DashboardView,
    AdvancedSearchListView,
    AdvancedSearchCreateView,
    AdvancedSearchUpdateView,
    AdvancedSearchDeleteView,
    CategoryListView,
    CategoryCreateView,
    CategoryUpdateView,
    CategoryDeleteView
)
from django.urls import path


urlpatterns = [
    # Orchestrator dashboard
    path('', DashboardView.as_view(), name='orchestrator-dashboard'),

    # Advanced search
    path('advancedsearch/', AdvancedSearchListView.as_view(), name='advancedsearch_list'),
    path('advancedsearch/new/', AdvancedSearchCreateView.as_view(), name='advancedsearch_create'),
    path('advancedsearch/<int:pk>/edit/', AdvancedSearchUpdateView.as_view(), name='advancedsearch_edit'),
    path('advancedsearch/<int:pk>/delete/', AdvancedSearchDeleteView.as_view(), name='advancedsearch_delete'),

    # Categories for advanced search queries
    path('advancedsearch/category/', CategoryListView.as_view(), name='category_list'),
    path('advancedsearch/category/create/', CategoryCreateView.as_view(), name='category_create'),
    path('advancedsearch/category/<int:pk>/edit/', CategoryUpdateView.as_view(), name='category_edit'),
    path('advancedsearch/category/<int:pk>/delete/', CategoryDeleteView.as_view(), name='category_delete'),
]
