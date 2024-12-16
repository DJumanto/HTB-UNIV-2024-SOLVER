from django.core.management.base import BaseCommand
from django.utils import timezone
from contracts.models import User, Contract
from django.db import transaction
import random
import string

class Command(BaseCommand):
    help = 'Clears the database and seeds it with initial data for testing'

    def handle(self, *args, **options):
        def generate_password(length=32):
            chars = string.ascii_lowercase
            return ''.join(random.choice(chars) for _ in range(length))


        User.objects.all().delete()
        Contract.objects.all().delete()

        with transaction.atomic():
            admin_password = generate_password()
            manager_password = generate_password()

            admin_user = User.objects.create_superuser(username="admin", password=admin_password)
            contract_manager_user = User.objects.create_user(
                username="contract_manager", 
                password=manager_password, 
                role=User.Role.CONTRACT_MANAGER
            )

            contracts_data = [
                {
                    "title": "Contract for Frontier Cluster Security",
                    "description": "Contract to provide enhanced security across the Frontier Cluster.",
                    "start_date": timezone.now().date(),
                    "end_date": timezone.now().date(),
                    "status": Contract.Status.ACTIVE,
                    "owner": admin_user,
                    "terms": "All operations must comply with intergalactic security protocols.",
                    "amount": 50000.00
                },
                {
                    "title": "Exploration Contract for Sector 7",
                    "description": "Exploration mission to map unknown regions in Sector 7.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.PENDING_REVIEW,
                    "owner": contract_manager_user,
                    "terms": "Mission requires complete mapping of Sector 7 within the designated timeframe.",
                    "amount": 75000.00
                },
                {
                    "title": "Supply Chain Management for Outpost Alpha",
                    "description": "Management and logistics contract for supplying Outpost Alpha.",
                    "start_date": timezone.now().date(),
                    "end_date": timezone.now().date(),
                    "status": Contract.Status.DRAFT,
                    "owner": admin_user,
                    "terms": "Regular shipments of essential supplies.",
                    "amount": 30000.00
                },
                {
                    "title": "Medical Supplies Delivery to Frontier Outpost",
                    "description": "Contract to deliver medical supplies to remote Frontier Outpost.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.COMPLETED,
                    "owner": contract_manager_user,
                    "terms": "All supplies must be delivered in temperature-controlled containers.",
                    "amount": 15000.00
                },
                {
                    "title": "Research and Development for Starry Spur Project",
                    "description": "R&D contract for finding the legendary Starry Spur.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.APPROVED,
                    "owner": admin_user,
                    "terms": "Maintain secrecy and security throughout the project.",
                    "amount": 100000.00
                },
                {
                    "title": "Defense System Upgrade for Frontier Outposts",
                    "description": "Upgrade defense systems at multiple outposts.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.ACTIVE,
                    "owner": contract_manager_user,
                    "terms": "Implement cutting-edge security measures.",
                    "amount": 60000.00
                },
                {
                    "title": "Interstellar Communication Network Expansion",
                    "description": "Expand communication networks across the Frontier Cluster.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.PENDING_REVIEW,
                    "owner": admin_user,
                    "terms": "Ensure compatibility with existing systems.",
                    "amount": 90000.00
                },
                {
                    "title": "Advanced AI Research for Frontier Defense",
                    "description": "Research AI systems for enhancing defense capabilities.",
                    "start_date": timezone.now().date(),
                    "status": Contract.Status.DRAFT,
                    "owner": contract_manager_user,
                    "terms": "Develop AI models to enhance security.",
                    "amount": 85000.00
                }
            ]

            for contract_data in contracts_data:
                Contract.objects.create(**contract_data)
