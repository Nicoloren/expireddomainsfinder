# -*- coding: utf-8 -*-
# library to manage SQLITE3 database
# Nicolas Lorenzon - nicolas@lorenzon.ovh - http://www.lorenzon.ovh

import sqlite3

class storage(object):

    def __init__(self):
        self.connexion = None
        self.connexionBase()
        
    # connect to sqlite3 database
    def connexionBase(self):
        self.connexion = sqlite3.connect(":memory:", timeout=180)
        self.connexion.execute("CREATE TABLE 'urls' ('id' INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL , 'url' TEXT UNIQUE , 'crawled' INTEGER DEFAULT 0);")


    # format text before insert in database
    def prepareExpression(self, expression):
        return expression.replace("\"", "\"\"").strip()


    # get all records from database
    def lectureTous(self):
        #conn = connexionBase(basedonnees)
        requete = "SELECT * FROM urls;"
        cursor = self.connexion.execute(requete)
        tableau = list()
        for ligne in cursor:
            tableau.append(ligne)
        return tableau


    # get all records not crawled
    def lectureToCrawl(self):
        requete = "SELECT * FROM urls WHERE crawled = 0;"
        cursor = self.connexion.execute(requete)
        tableau = list()
        for ligne in cursor:
            tableau.append(ligne)
        return tableau


    # ajout d'une url dans la basedonnees
    def addUrl(self,url) :
        try:
            requete = "INSERT INTO urls (url) VALUES (\"" + str(url) + "\");"
            self.connexion.execute(requete)
            return 1
        except:
            #print("on a pas réussi l'ajout : " + str(url))
            return 0


    # un seul enregistrement
    def lectureUneUrl(self):
        # en cas d'erreur de lock de la base
        requete = "SELECT * FROM urls WHERE crawled = 0 LIMIT 1;"
        cursor = self.connexion.execute(requete)
        tableau = cursor.fetchone()
        if tableau is not None :
            url = tableau[1]
            # mise à jour
            self.connexion.execute( "UPDATE urls SET crawled = 1 WHERE url = \"" + self.prepareExpression(url) + "\" ;")
        else :
            url = None
        
        return url
        
    # mise à jour pour dire qu'on a crawlé l'url
    def majUrl(self,url) :
        #conn = connexionBase(basedonnees)
        self.connexion.execute( " UPDATE urls SET crawled = 1 WHERE url = \"" + self.prepareExpression(url) + "\" ;")
        

    def supprimeTout(self) :
        #conn = connexionBase(basedonnees)
        self.connexion.execute("DELETE FROM urls ;")
        self.connexion.execute("VACUUM")   
        self.connexion.execute("UPDATE SQLITE_SEQUENCE SET SEQ=0 WHERE NAME='urls';")