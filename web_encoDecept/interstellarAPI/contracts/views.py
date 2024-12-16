from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .models import User, ContractTemplate, Contract
from .serializers import UserSerializer, ContractSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from .permissions import IsContractManagerOrAdmin, IsAdministrator
import base64
from django.utils import timezone
from threading import Thread
from .util import startChromiumBot

class SubmitReportView(APIView):
    def post(self, request):
        contract_url = request.data.get("contract_url")
        if contract_url:
            Thread(target=startChromiumBot, args=(contract_url,)).start()
            return Response({"message": "Report submitted successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = {
            "username": user.username,
            "bio": user.bio,
            "role": user.role,
            "id": user.id
        }
        return Response(user_data)

    def patch(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Create user with plain-text password
        user = User.objects.create_user(username=username, password=password)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
            if user.password != password:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class UserContractsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        contracts = Contract.objects.filter(owner=request.user)
        serializer = ContractSerializer(contracts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AllContractsView(APIView):
    permission_classes = [IsAuthenticated, IsContractManagerOrAdmin]

    def get(self, request):
        contracts = Contract.objects.all()
        serializer = ContractSerializer(contracts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FilteredContractsView(APIView):
    permission_classes = [IsAuthenticated, IsContractManagerOrAdmin]

    def post(self, request, format=None):
        try:
            if request.data.get("all") == True:
                contracts = Contract.objects.all()
            else:
                filtered_data = {key: value for key, value in request.data.items() if key != "all"}
                contracts = Contract.objects.filter(**filtered_data)
                
            serializer = ContractSerializer(contracts, many=True)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response(serializer.data, status=status.HTTP_200_OK)

class ContractDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            contract = Contract.objects.get(id=id)
            if request.user.role == 'guest' and contract.owner != request.user:
                return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
            
            serializer = ContractSerializer(contract)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Contract.DoesNotExist:
            return Response({"error": "Contract not found"}, status=status.HTTP_404_NOT_FOUND)

class ContractCreateView(APIView):
    def post(self, request):
        serializer = ContractSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StoreContractTemplateView(APIView):
    permission_classes = [IsAuthenticated, IsAdministrator]
    def get(self, request):
        try:
            templates = ContractTemplate.objects.all()
            serialized_templates = [
                {
                    "id": template.id,
                    "name": template.name,
                    "description": template.description,
                    "data": template.data,
                    "created_at": template.created_at,
                    "updated_at": template.updated_at,
                    "user": template.user.id if template.user else None
                }
                for template in templates
            ]
            return Response(serialized_templates, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        serialized_data = request.data.get("data")
        name = request.data.get("name")
        description = request.data.get("description")
        user_id = request.data.get("user_id")

        try:
            user = User.objects.get(id=user_id)
            ContractTemplate.objects.create(
                name=name,
                description=description,
                data=serialized_data,
                created_at=timezone.now(),
                user=user
            )
            return Response({"message": "Template stored successfully"}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ContractTemplateDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAdministrator]

    def get(self, request, template_id):
        try:
            template = ContractTemplate.objects.get(id=template_id)
            serialized_data = {
                "id": template.id,
                "name": template.name,
                "description": template.description,
                "data": template.data,
                "created_at": template.created_at,
                "updated_at": template.updated_at,
                "user": template.user.id if template.user else None
            }
            return Response(serialized_data, status=status.HTTP_200_OK)
        except ContractTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, template_id):
        try:
            template = ContractTemplate.objects.get(id=template_id)
            template.name = request.data.get("name", template.name)
            template.description = request.data.get("description", template.description)
            template.data = request.data.get("data", template.data)
            template.updated_at = timezone.now()
            template.save()
            return Response({"message": "Template updated successfully"}, status=status.HTTP_200_OK)
        except ContractTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, template_id):
        try:
            template = ContractTemplate.objects.get(id=template_id)
            template.delete()
            return Response({"message": "Template deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except ContractTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)
