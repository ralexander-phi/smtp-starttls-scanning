from django.db import models


class MailHost(models.Model):
    name = models.CharField(max_length=256, primary_key=True)
    reachable = models.BooleanField()
    error = models.IntegerField(null=True)
    starttls = models.BooleanField(null=True)
    pkix_trusted = models.BooleanField(null=True)


class Domain(models.Model):
    name = models.CharField(max_length=256, primary_key=True)
    mail_hosts = models.ManyToManyField(MailHost)

