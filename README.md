---

## 👤 Auteur

- **Sefiane El-kassimi**  
  Master MMSD – Année universitaire 2024–2025

---

## 🧑‍🏫 Encadrement

- **Encadrant pédagogique :** Mr **AZMANI Abdellah**  
- **Responsable du module :** Mme **LECHHAB OUADRASSI Nihad**

---

## 📝 Remarques

Ce projet est une **preuve de concept académique**, réalisé dans un but **pédagogique**.  
⚠️ **Il ne doit pas être utilisé en production sans mesures de sécurité supplémentaires.**

 
 # 📌 Projet : Mise en œuvre d’une Infrastructure à Clés Publiques (PKI) à Trois Niveaux

> Ce projet a pour objectif de :
>
> - Comprendre et mettre en œuvre la hiérarchie et la chaîne de confiance dans une PKI.
> - Générer, signer et distribuer des certificats numériques dans une architecture à trois niveaux.
> - Gérer la sécurité des clés privées et appliquer les bonnes pratiques liées aux certificats.
> - Implémenter la gestion des demandes de signature (CSR) et la révocation des certificats (CRL).
> - Proposer une interface d’utilisation simplifiée (GUI) pour gérer les opérations clés de la PKI.
> - Vérifier la validité et la chaîne de confiance des certificats générés.
>
> Réalisé dans le cadre du module **Cryptographie & Blockchain** du master **MMSD**.

---

## 🛠️ Technologies et bibliothèques utilisées

- **Python 3.x**
- **Flask** – Framework web léger
- **cryptography** – Pour la génération et gestion des clés RSA, certificats X.509, CSR, CRL
- **Werkzeug** – Pour la gestion des mots de passe hashés
- **SQLite3** – Pour le stockage local des données
- **dotenv** – Pour la gestion sécurisée des variables d’environnement
- **uuid**, **datetime**, **os**, **io**, **functools** – Modules standards de Python

---

## 📁 Structure du projet (exemple)
pki-flask-app/
│
├── app.py # Application principale Flask
│
├── root-ca/ # Autorité de certification racine (Root CA)
├── intermediate-ca/ # Autorité intermédiaire (Intermediate CA)
├── leaf-certs/ # Certificats finaux émis pour les utilisateurs ou serveurs
├── certificates/ # Emplacement global des certificats générés et enregistrés
│
├── certs/ # Autres fichiers liés aux certificats si utilisés
├── templates/ # Fichiers HTML (interface utilisateur)
├── static/ # Fichiers CSS, JS, images
│
├── database/ # Données locales et base SQLite
│ └── pki.db
│
├── .env # Variables d’environnement (chemins, clés, secrets)
├── requirements.txt # Liste des dépendances Python
└── README.md # Documentation du projet


