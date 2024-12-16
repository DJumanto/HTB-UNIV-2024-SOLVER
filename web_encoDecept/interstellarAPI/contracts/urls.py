# urls.py

from django.urls import path
from .views import ContractTemplateDetailView, StoreContractTemplateView, ContractCreateView, SubmitReportView, RegisterView, LoginView, UserContractsView, AllContractsView, FilteredContractsView, ContractDetailView, UserDetailView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('contract/', UserContractsView.as_view(), name='user-contracts'),
    path('all/', AllContractsView.as_view(), name='all-contracts'),
    path('contracts/filter/', FilteredContractsView.as_view(), name='filtered-contracts'),
    path('contracts/<int:id>/', ContractDetailView.as_view(), name='contract-detail'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('submit_report/', SubmitReportView.as_view(), name='submit_report'),
    path('contracts/', ContractCreateView.as_view(), name='contract-create'),
    path('contract_templates/', StoreContractTemplateView.as_view(), name='create_contract_template'),
    path('contract_templates/<int:template_id>/', ContractTemplateDetailView.as_view(), name='contract_template_detail'),
]
