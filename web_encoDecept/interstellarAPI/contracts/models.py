from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.conf import settings
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, username, password=None, role="guest", bio=None):
        if not username:
            raise ValueError("Users must have a username")
        if role not in [choice[0] for choice in User.Role.choices]:
            raise ValueError("Invalid role selected")

        user = self.model(username=username, role=role, bio=bio, password=password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None):
        return self.create_user(username=username, password=password, role="administrator")


class User(AbstractBaseUser):
    class Role(models.TextChoices):
        ADMINISTRATOR = "administrator", "Administrator"
        CONTRACT_MANAGER = "contract_manager", "Contract Manager"
        GUEST = "guest", "Guest"

    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=100)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.GUEST)
    bio = models.TextField(blank=True, null=True, help_text="User biography in Markdown format.")

    objects = UserManager()

    USERNAME_FIELD = 'username'

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

class Contract(models.Model):
    class Status(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        PENDING_REVIEW = 'pending_review', 'Pending Review'
        APPROVED = 'approved', 'Approved'
        ACTIVE = 'active', 'Active'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'

    title = models.CharField(max_length=200, help_text="Title of the contract")
    description = models.TextField(help_text="Detailed description of the contract")
    start_date = models.DateField(help_text="Start date of the contract")
    end_date = models.DateField(help_text="End date of the contract", null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
        help_text="Current status of the contract"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='contracts',
        help_text="User who owns the contract"
    )

    terms = models.TextField(help_text="Terms and conditions of the contract")
    amount = models.DecimalField(max_digits=10, decimal_places=2, help_text="Total contract amount")
    attachments = models.FileField(upload_to='contracts/attachments/', null=True, blank=True, help_text="Any associated documents or files")

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

class ContractTemplate(models.Model):
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(help_text="Description of the contract template", null=True, blank=True)
    data = models.TextField(help_text="Serialized contract template data", null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="contract_templates", null=True)

    def __str__(self):
        return f"{self.name} by {self.user.username}"
