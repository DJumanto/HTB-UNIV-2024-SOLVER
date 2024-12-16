# contracts/permissions.py

from rest_framework.permissions import BasePermission

class IsContractManagerOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.role in ['contract_manager', 'administrator']

class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        return request.user.role in ['administrator']