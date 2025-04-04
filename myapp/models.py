from django.db import models

class Alert(models.Model):
    alert_id = models.AutoField(primary_key=True)
    #id = models.IntegerField()
    time = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=8, choices=[('low', 'low'), ('medium', 'medium'), ('critical', 'critical')])
    computer = models.CharField(max_length=255)
    account_name = models.CharField(max_length=255, null=True, blank=True)
    source = models.CharField(max_length=50)
    #destination = models.CharField(max_length=50, null=True, blank=True)
    description = models.TextField()
    status = models.CharField(max_length=25, default='Pending')
    full_alert = models.TextField()
    full_response = models.TextField()
    response_desc = models.TextField()
    responder = models.TextField()

    class Meta:
        db_table = 'alert'

    def __str__(self):
        return f"Alert {self.alert_id} - {self.timestamp}"
from django.db import models

class Feature(models.Model):
    name = models.CharField(max_length=50)
    details = models.CharField(max_length=200)
    image = models.CharField(max_length=300)
