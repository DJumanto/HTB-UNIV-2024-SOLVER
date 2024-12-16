# contracts/serializers.py

from rest_framework import serializers
from .models import User, Contract, ContractTemplate

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'bio', 'password', 'id']
        extra_kwargs = {'password': {'write_only': True}}  # Ensure password is not exposed

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data.pop('password'))  # Hash the password
        return super().update(instance, validated_data)

class ContractSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contract
        fields = ['id', 'title', 'description', 'start_date', 'end_date', 'status', 'terms', 'amount', 'attachments', 'created_at', 'updated_at']
