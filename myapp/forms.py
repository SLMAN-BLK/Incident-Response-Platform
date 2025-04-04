from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

from django import forms

# Form for updating username and email
class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']