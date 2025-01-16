import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Informations de connexion
smtp_server = "smtp.gmail.com"  # Serveur SMTP de Gmail
smtp_port = 587  # Port pour TLS
email_address = "nextflix.gros@gmail.com"  # Remplacez par votre adresse email
email_password = "Haribocestbeaulavieplgelp."  # Remplacez par votre mot de passe

# Configuration de l'email
recipient_email = "corentin.delpree@ynov.com"  # Adresse email du destinataire
subject = "BATARD VA "
body = "CE soir HIGH ET FINES HERBES CA FUME"

# Création de l'objet email
message = MIMEMultipart()
message["From"] = email_address
message["To"] = recipient_email
message["Subject"] = subject
message.attach(MIMEText(body, "plain"))

try:
    # Connexion au serveur SMTP
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Sécurise la connexion
        server.login(email_address, email_password)  # Authentification
        server.send_message(message)  # Envoi de l'email
        print("Email envoyé avec succès !")
except Exception as e:
    print(f"Erreur lors de l'envoi de l'email : {e}")