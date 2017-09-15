# -*- coding: utf-8 -*-
# library to manage GUI 
# Nicolas Lorenzon - nicolas@lorenzon.ovh - http://www.lorenzon.ovh

from tkinter import *
from tkinter.ttk import *
from tkinter.messagebox import *
from tkinter.filedialog import askopenfilename
import threading, socket, gc
from socket import error as SocketError
import urllib.request
from urllib.parse import urlparse
from urllib.parse import urljoin
import time, random, queue
import os.path
import lxml.html
import pickle
#librairie pour les accès à la base de données
#import lib_bd
# pip install pyscape-client
from pyscape import Pyscape
import webbrowser
#from vprof import profiler
#from memory_profiler import profile
#from pympler import tracker
# pip install python-whois 
import whois
# pip install dnspython
import dns.resolver
# pour l'ouverture en écriture et utf-8
import codecs
# pour faire des liens 
import tkHyperlinkManager

class MyQueue(queue.Queue): # or OrderedSetQueue
    def __contains__(self, item):
        with self.mutex:
            return item in self.queue


class myGui(object):

    def __init__(self):
        
        self.fenetre = None

        # tree des sites fentre générale
        self.tree = None

        self.idModification = None
        self.idModificationAction = None

        self.entryUrl = None
        self.entrySearch = None
        self.entryCheck = None
        self.entryThreads = None
        # zone de texte
        self.textLog = None
        # zone de texte whois et dns 
        self.textWhois = None

        self.moz_access_id = None
        self.moz_secret_id = None
        self.user_agent = None
        
        self.label_compteur = None

        self.termes_a_exclure = None

        #self.toutesUrl = [] # toutes les urls trouvées
        #self.toutesUrlChecked = [] # toutes les urls vérifiées
        #self.toutesUrlCrawled = [] # toutes les urls crawlées
        #self.toutesUrlNew = [] # toutes les urls qu'on doit crawler dans le FutureWarning

        # réécriture pour tirer un meilleur parti des threads
        # réécriture avec des Queues
        self.toutesUrlFinded = [] # toutes les urls qu'on a trouvé et qui s'affichent dans la liste

        self.queueUrls = None  # toutes les urls connues
        self.queueUrlsChecked = None # celles qui ont été vérifiées
        self.queueUrlsCrawled = None # celles qui ont été crawlées
        self.queueUrlsAttente = None # celles qu'on doit crawler

        
        self.tousThreads = [] # tous les threads en cours
        
        self.thread = None

        self.stopThread = False

        self.initialisation()
        self.addWidgets()
        self.runLoop()
        
        self.nombre = None
        self.nombreTrouve = None
        self.nombreThreads = None
        self.connexion = None
        
        self.numberOfThreads = None 
        
        self.nomfichier = None
        
        # les checkbox
        self.erreur404 = None
        self.erreur500 = None
        self.erreur403 = None
        self.erreurExpired = None
        self.erreurAll = None 
        
        self.varErreur403 = None
        self.varErreur404 = None 
        self.varErreur500 = None
        self.varErreurExpired = None
        self.varErreurAll = None
        # radio bouton
        self.radioDomain = None
        self.varRadioDomain = None
        # gestionnaire de liens 
        self.hyperlink = None

        
    def initialisation(self) :
        # init GUI
        self.fenetre = Tk()
        #self.fenetre.iconbitmap(ICON_PATH)
        self.fenetre.title("Expired Domains Finder version 20160802 - 64bits")
        self.fenetre.geometry("1200x600")
        self.nombre = 0
        self.nomfichier = "expired.txt"
        # pour les checkbox erreurs
        self.varErreur403 = IntVar()
        self.varErreur404 = IntVar()
        self.varErreur500 = IntVar()
        self.varErreurExpired = IntVar()
        self.varErreurAll = IntVar()
        self.varErreurExpired.set(1)
        # pour le radio bouton
        self.varRadioDomain = IntVar()
        self.varRadioDomain.set(2)
        self.numberOfThreads = 50
        
    # pour restaurer la session en cours 
    def restoreSession(self) :
        self.logMessage("restauration de la session")
        try :
            with open('previous.sav', 'rb') as f:
                temp = pickle.load(f)

                self.entryUrl.delete(0, END)
                self.entryUrl.insert(0, temp["entryurl"])

                self.entrySearch.delete(0, END)
                self.entrySearch.insert(0,  temp["entrysearch"])

                self.entryCheck.delete(0, END)
                self.entryCheck.insert(0,  temp["entrycheck"])

                self.toutesUrl = temp["toutesurl"]
                self.toutesUrlChecked =  temp["toutesurlchecked"]
                self.toutesUrlCrawled =  temp["toutesurlcrawled"]
                self.toutesUrlNew =  temp["toutesurlnew"]
                self.toutesUrlFinded =  temp["toutesurlfinded"]

                self.varRadioDomain.set(temp["varradiodomain"])
                self.varErreurExpired.set(temp["varerreurexpired"])
                self.varErreur403.set(temp["varerreur403"])
                self.varErreur404.set(temp["varerreur404"])
                self.varErreur500.set(temp["varerreur500"])
                self.varErreurAll.set(temp["varerreurall"])

            return True
        except Exception :
            self.logMessage("erreur restauration pickle")
            return False  


    def savePickle(self, data, file) :
        with open(file, 'wb') as f:
            # Pickle the 'data' dictionary using the highest protocol available.
            pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)

    
    # pour sauvegarder la session en cours 
    def saveSession(self) :
        self.logMessage("sauvegarde de la session")
        # on sauvegarde un par un tous les fichiers dans le repertoire courant
        temp = {}
        temp["entryurl"] = self.entryUrl.get()
        temp["entrysearch"] = self.entrySearch.get()
        temp["entrycheck"] = self.entryCheck.get()
        temp["toutesurl"] = self.toutesUrl
        temp["toutesurlchecked"] = self.toutesUrlChecked
        temp["toutesurlcrawled"] = self.toutesUrlCrawled
        temp["toutesurlnew"] = self.toutesUrlNew
        temp["toutesurlfinded"] = self.toutesUrlFinded

        temp["varradiodomain"] = self.varRadioDomain.get()
        temp["varerreurexpired"] = self.varErreurExpired.get()
        temp["varerreur403"] = self.varErreur403.get()
        temp["varerreur404"] = self.varErreur404.get()
        temp["varerreur500"] = self.varErreur500.get()
        temp["varerreurall"] = self.varErreurAll.get()

        self.savePickle(temp, 'previous.sav')
        temp.clear()
        del temp
        
    # Fonction qui va lire un fichier et retourner toutes les lignes
    def lireFichier(self, fichier) :
        content = None
        try:
            with open(fichier,encoding='utf-8') as f:
                content = f.readlines()
        except Exception:
            self.logMessage("impossible de lire le fichier avec utf-8")
        if content == None :
            try:
                with open(fichier,encoding='latin-1') as f:
                    content = f.readlines()
            except Exception:
                self.logMessage("impossible de lire le fichier avec latin-1")
        return content
        
    # lecture du fichier de configuration s'il existe
    # renvoie un couple d'éléments : site et config
    def readConfig(self) :
         website = "http://www.seosoftwarenow.com"
         moz_access_id=""
         moz_secret_id=""
         search="seosoftwarenow.com"
         check="."
         threads="50"
         userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36'
         if (os.path.isfile("config.cfg")) :
             #print("fichier config trouvé")
             contenu = self.lireFichier("config.cfg")
             #print(contenu)
             for ligne in contenu :
                 # on regarde si on trouve les mots clés
                 if ("SITE=" in ligne) :
                     website = ligne.replace("SITE=", "").replace("\n", "").replace(" ", "")
                 if ("SEARCH=" in ligne) :
                     search = ligne.replace("SEARCH=", "").replace("\n", "").replace(" ", "")
                 if ("CHECK=" in ligne) :
                     check = ligne.replace("CHECK=", "").replace("\n", "").replace(" ", "")
                 if ("MOZ_ACCESS_ID=" in ligne) :
                     moz_access_id = ligne.replace("MOZ_ACCESS_ID=", "").replace("\n", "").replace(" ", "")
                 if ("MOZ_SECRET_ID=" in ligne) :
                     moz_secret_id = ligne.replace("MOZ_SECRET_ID=", "").replace("\n", "").replace(" ", "")
                 if ("USER_AGENT=" in ligne):
                     userAgent = ligne.replace("USER_AGENT=", "").replace("\n", "").replace(" ", "")
                 if ("THREADS=" in ligne):
                     threads = ligne.replace("THREADS=", "").replace("\n", "").replace(" ", "")
         else :
             print("fichier config non trouvé")
                      
         return website, search, moz_access_id, moz_secret_id, userAgent, check, int(threads)

    def quitter(self) :
        try:
            self.stopcrawl()
        except Exception :
            self.logMessage("erreur lors de l'arrête des threads")
        self.fenetre.quit()


    def importWebsite(self):
        # lecture du fichier csv
        # l fichier doite être de la forme toto;titi;tralala;
        fname = askopenfilename(filetypes=(("TXT", "*.txt"),
                                           ("All files", "*.*")))
        try:
            contenu_fichier_website = self.lireFichier(fname)
        except:
            showerror("File error", "Error reading file " + fname)
            return -1
        lesUrls = ""
        nombre = 0
        for ligne in contenu_fichier_website:
            element = ligne.replace("\n", " ")
            if nombre > 0 :
                lesUrls = lesUrls + "|"
            if len(element) > 0:
                lesUrls = lesUrls + element
            nombre += 1
        self.entryUrl.insert(0, lesUrls)
        

    # ajout des widget sur la fenetre principale des sites
    def addWidgets(self) :

        # ajout des paramètres d'url -------------------------------------------
        frame1 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame1.pack(side=TOP, padx=5, pady=5, expand=False, fill=X)

        bouton=Button(frame1, text="Quit", command=self.quitter)
        bouton.pack(side="right", padx=5, pady=5)

        button = Button(frame1, text="Start New", command=self.crawl)
        button.pack(side="left", padx=5, pady=5)

        button = Button(frame1, text="Resume", command=self.resume)
        button.pack(side="left", padx=5, pady=5)

        button = Button(frame1, text="Stop", command=self.stopcrawl)
        button.pack(side="left", padx=5, pady=5)

        button = Button(frame1, text="Import URLs", command=self.importWebsite)
        button.pack(side="left", padx=5, pady=5)

        # lecture de la configuration
        websiteConfig, search, self.moz_access_id, self.moz_secret_id, self.user_agent, check, self.numberOfThreads = self.readConfig()
        
        w = Label(frame1, text="URLs to crawl (separated with '|') : ")
        w.pack(side="left", padx=5, pady=5)
        
        self.entryUrl = Entry(frame1, width=30)
        self.entryUrl.pack(side="left", fill=X, expand=True)
        self.entryUrl.insert(0, websiteConfig)
        
        # ajout des paramètres d'exclusions et autres -----------------------------

        # pour la liste d'exclusion
        frame3 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame3.pack(side=TOP, padx=5, pady=5, expand=False, fill=X)

        w = Label(frame3, text="Crawl URLs that contains (example : 'tumblr.com') : ")
        w.pack(side="left", padx=5, pady=5)

        self.entrySearch = Entry(frame3, width=30)
        self.entrySearch.pack(side="left", fill=X, expand=True)
        self.entrySearch.insert(0, search)
        
        # pour savoir ce qu'on doit rechercher
        w = Label(frame3, text="Check URLs that contains (example : 'tumblr.com') : ")
        w.pack(side="left", padx=5, pady=5)

        self.entryCheck = Entry(frame3, width=30)
        self.entryCheck.pack(side="left", fill=X, expand=True)
        self.entryCheck.insert(0, check)
        
        # pour le reste des options 
        frame5 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame5.pack(side=TOP, padx=5, pady=5, expand=False, fill=X)
        
        # pour le radio boutton
        w = Label(frame5, text=" ★ Check : ")
        w.pack(side="left", padx=5, pady=5)
        
        self.radioDomain = Radiobutton(frame5, text="URL", variable=self.varRadioDomain, value=1)
        self.radioDomain.pack(side="left", padx=5, pady=5)
        
        self.radioDomain = Radiobutton(frame5, text="Domain / Subdomain", variable=self.varRadioDomain, value=2)
        self.radioDomain.pack(side="left", padx=5, pady=5)
        
        # checkbox
        w = Label(frame5, text=" ★ Search for error(s) : ")
        w.pack(side="left", padx=5, pady=5)

        self.erreurExpired = Checkbutton(frame5, text="Expired (recommanded)", variable=self.varErreurExpired)
        self.erreurExpired.pack(side="left", padx=5, pady=5)

        self.erreur403 = Checkbutton(frame5, text="403", variable=self.varErreur403)
        self.erreur403.pack(side="left", padx=5, pady=5)
        
        self.erreur404 = Checkbutton(frame5, text="404", variable=self.varErreur404)
        self.erreur404.pack(side="left", padx=5, pady=5)
        
        self.erreur500 = Checkbutton(frame5, text="500", variable=self.varErreur500)
        self.erreur500.pack(side="left", padx=5, pady=5)

        self.erreurAll = Checkbutton(frame5, text="All", variable=self.varErreurAll)
        self.erreurAll.pack(side="left", padx=5, pady=5)

        w = Label(frame5, text=" ★ Number of threads : ")
        w.pack(side="left", padx=5, pady=5)

        self.entryThreads = Entry(frame5, width=4)
        self.entryThreads.pack(side="left", fill=X, expand=True)
        self.entryThreads.insert(0, str(self.numberOfThreads) )

        button = Button(frame5, text="Open expired domains file", command=self.cliqueOuvrirFichier)
        button.pack(side="right", padx=5, pady=5)
        
        # frame qui va contenir la liste des domaines et l'affichage du whois et dns a côté
        frame_generale = Frame(self.fenetre, borderwidth=0)
        frame_generale.pack(side=TOP, padx=0, pady=0, expand=True, fill=BOTH)

        # frame qui a contenir la zone de texte pour DND et whois 
        frame_whois = Frame(frame_generale, borderwidth=2, relief=GROOVE)
        frame_whois.pack(side=RIGHT, padx=5, pady=5, expand=True, fill=BOTH)

        scrollbar = Scrollbar(frame_whois)
        scrollbar.pack(side = RIGHT, fill=Y )
        
        self.textWhois = Text(frame_whois,width = 20, height=2)
        self.textWhois.pack(side="right", padx=5, pady=5, expand=True, fill=BOTH)
        
        scrollbar.config(command=self.textWhois.yview)
        self.textWhois.config(yscrollcommand=scrollbar.set)

        self.textWhois.insert('0.0', "Click on the left to print Whois info" + "\n")

        # gestion des liens
        self.hyperlink = tkHyperlinkManager.HyperlinkManager(self.textWhois)

        # affichage de la liste des pages parcourues
        #frame2 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame2 = Frame(frame_generale, borderwidth=2, relief=GROOVE)
        frame2.pack(side=LEFT, padx=5, pady=5, expand=True, fill=BOTH)

        scrollbar = Scrollbar(frame2)
        scrollbar.pack(side = RIGHT, fill=Y )

        self.tree = Treeview(frame2)
        self.tree.heading('#0', text='Domains (click to see details in right panel)')
        self.tree.column("#0",minwidth=200,width=300, stretch=YES)
        self.tree.pack(side="right", padx=5, pady=5, expand=True, fill=BOTH)

        scrollbar.config(command=self.tree.yview)
        self.tree.config(yscrollcommand=scrollbar.set)

        #self.tree.bind("<Double-1>", self.afficheURL)
        #self.tree.bind("<Button-1>", self.afficheWhois)
        # <<TreeviewSelect>>
        self.tree.bind("<<TreeviewSelect>>", self.afficheWhois)

        # zone de texte pour la log
        frame6 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame6.pack(side=TOP, padx=5, pady=5, expand=True, fill=BOTH)
        
        scrollbar = Scrollbar(frame6)
        scrollbar.pack(side = RIGHT, fill=Y )
        
        self.textLog = Text(frame6,width = 30, height=2)
        self.textLog.pack(side="right", padx=5, pady=5, expand=True, fill=BOTH)
        self.logMessage("Init... ok.", True)
        
        scrollbar.config(command=self.textLog.yview)
        self.textLog.config(yscrollcommand=scrollbar.set)
        
        # frame avec compteur
        frame4 = Frame(self.fenetre, borderwidth=2, relief=GROOVE)
        frame4.pack(side=TOP, padx=5, pady=5, expand=False, fill=X)

        self.label_compteur = StringVar()
        w = Label(frame4, textvariable=self.label_compteur)
        w.pack(side="right", padx=5, pady=5)
        self.label_compteur.set("0 url crawled")

        w = Label(frame4, text="Use at your own risk - Get help on SeoSoftwareNow.com")
        w.pack(side="left", padx=5, pady=5)
        
        # on charge le fichier contenant les domaines déjà trouvés
        self.toutesUrlFinded = []
        self.loadFileChecked()

    def cliqueOuvrirFichier(self) :
        webbrowser.open(self.nomfichier)

    # affiche les infos de whois lors d'un clic sur la liste
    def afficheWhois(self, event):
        # pour afficher le whois et les DNS (éventuellement)
        # pour la ligne sélectionnée de la liste
        #self.fenetre.config(cursor="watch")

        try :
            item = self.tree.selection()[0]
            #self.logMessage(str(item))
        except Exception :
            #self.fenetre.config(cursor="")
            return False

        ligne = self.tree.item(item, "text")
        url = ligne.split("|")[0].replace(" ", "")

        parsed_uri = urlparse(url)
        url = '{uri.netloc}'.format(uri=parsed_uri)

        self.logMessage(url)
        try :
            w = whois.whois(url)
        except whois.parser.PywhoisError as erreur :
            w = str(erreur)
        except Exception :
            w = "Unknown error (need manual check)"
        
        data_dns = ""
        try :
            answers = dns.resolver.query(url, 'MX')
            for rdata in answers:
                data_dns = data_dns + 'Host ' + str(rdata.exchange) + ' has preference ' + str( rdata.preference) + "\n"
        except Exception :
            data_dns = "Unknown error in DNS checkup (need manual check)\n"
            print("erreur dns")

        self.textWhois.delete('1.0', END)
        self.textWhois.insert('0.0', "\n" + str(w) + "\n---\nDNS : \n"+ data_dns)

        self.textWhois.insert('0.0', str(url), self.hyperlink.add(self.afficheURL))
        #self.fenetre.config(cursor="")
       

    def logMessage(self, message, widget=False):
        #self.textLog.insert('end', message + "\n")
        if widget == True :
            self.textLog.insert('0.0', str(message) + "\n")
        else :
            print(str(message))
    
    # ouvre le navigateur pour afficher l'url
    def afficheURL(self) :
        item = self.tree.selection()[0]
        ligne = self.tree.item(item, "text")
        #self.logMessage(ligne)
        url = ligne.split("|")[0].replace(" ", "")
        #self.logMessage(url)
        webbrowser.open(url)

    def loadFileChecked(self) :
        if (os.path.isfile( self.nomfichier)) :
             #print("fichier config trouvé")
             contenu = self.lireFichier(self.nomfichier)
             #print(contenu)
             for ligne in contenu :
                 url = ligne.split("|")[0].replace(" ", "")
                 if url not in self.toutesUrlFinded :
                    self.tree.insert("",0, text=str(ligne))
                    self.toutesUrlFinded.append(url)
    
    
    def downloadURL(self, url, check):

        # on doit déjà regarder si c'est une url qui commence par http
        if ( not url.startswith("http") ) :
            return False 

        if check :
            self.logMessage("down url CHECK : " + url)

        if self.stopThread :
            self._is_running = False
            return

        # on va indiquer si on doit regarder le whois et les stats du domaine
        regardeWhois = False
        traitement = False

        try :
            if check :
                # on doit savoir si on vérifier le domaine ou toute l'url
                if self.varRadioDomain.get() == 2 :
                    parsed_uri = urlparse(url)
                    url = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
                    
                if url in self.queueUrlsChecked :
                    return False

                self.queueUrlsChecked.put(url)
                self.maj_compteur()
                self.logMessage("⌕ Check url : " + str(url), True)
            else :
                self.logMessage("⌛ Crawl url : " + str(url), True)
                if url not in self.queueUrlsCrawled :
                    self.queueUrlsCrawled.put(url)
            
            headers = { 'User-Agent' : self.user_agent, 'referer': url }
            data = urllib.parse.urlencode({})
            req = urllib.request.Request(url, data=None, headers=headers)
            html_page = urllib.request.urlopen(req).read()
            return html_page

        except urllib.error.URLError as e:
            
            print(e)
 
            # il y a eu une erreur
            if hasattr(e, 'code'):
            #if e.code : 
                if check :
                    codeerreur = str(e.code)
                    
                    self.logMessage("down url erreur : " + codeerreur)
                    whois_info = "Whois : ?"
                    
                    if self.varErreurAll.get() == 1 :
                        traitement = True
                    
                    if (codeerreur == "403" and self.varErreur403.get() == 1) :
                        #self.logMessage("403 passe")
                        traitement = True
                    if (codeerreur == "404" and self.varErreur404.get() == 1) :
                        #self.logMessage("404 passe")
                        traitement = True
                        regardeWhois = True
                            
                    if (codeerreur == "500" and self.varErreur500.get() == 1) :
                        #self.logMessage("500 passe")
                        traitement = True
                    
                    if url in self.toutesUrlFinded :
                        traitement = False
            else :
                # il n'y a pas de code mais un probleme quand même
                
                if hasattr(e, 'reason'):
                    print(str(e.reason))
                    regardeWhois = True
                    traitement = True
                    if self.varErreurExpired.get() == 1 :
                        codeerreur = "Address not reachable"      

        except urllib.error.URLError as e:
            #print(e.reason) 
            self.logMessage(" **** Erreur request **** : " + str(e.reason))
            
        except socket.timeout:
            self.logMessage(" **** Erreur request **** : socket.timeout")

        except socket.gaierror:
            self.logMessage(" **** Erreur request **** : socket.gaierror")
            regardeWhois = True 

        except SocketError as e:
            self.logMessage(" **** Erreur socket **** : " + str(e.errno))
            
        except Exception:
            self.logMessage(" **** Erreur - une autre exception bizarre...")

        resultat_whois = True
        if regardeWhois == True :
            # check whois pour être certain de son coup
            # retourne un texte ainsi qu'une valeur False si le whois a échoué
            whois_info, resultat_whois = self.checkWhois(url)
            
        # on chope le résultat de Moz PA et DA
        keys = {
            "access_id": self.moz_access_id,
            "secret_key": self.moz_secret_id
        }
        
        mozda = "?"
        mozpa = "?"
        mozlinks = "?"
        retour = ""
        if (self.moz_access_id != "" and self.moz_secret_id != "" and traitement) :
            try:
                p = Pyscape(**keys)
                resultat = p.get_url_metrics(url).json()
                mozda = str(round(resultat["pda"], 0))
                mozpa = str(round(resultat["upa"], 0))
                mozlinks = str(resultat["uid"])
                #self.logMessage(resultat)
                del keys
                del resultat
            except Exception :
                self.logMessage("Problem reading Moz Rank (have you correctly configured config.cfg ?)")

        # si on a demandé l'analyse d'erreurs 
        # ou si on est sur un check du domaine expiré et disponible uniquement
        affiche_dans_liste = False
        if traitement :
            # on ne cherche vraiment que les expirés
            if self.varErreurExpired.get() == 1 :
                # on affiche uniquement si le whois n'a rien donné et pas seulement s'il y a une erreur
                if  resultat_whois == False :
                    affiche_dans_liste = True
            else :
                affiche_dans_liste = True

        # si on affiche bien l'url trouvé dans la liste
        if affiche_dans_liste == True :
            if url not in self.toutesUrlFinded :
                self.toutesUrlFinded.append(url)
                temp = url + " | Error : " + codeerreur + " | DA : " + mozda + " | PA : " + mozpa + " | Links : " + mozlinks + " | " + whois_info
                self.tree.insert("",0, text=str(temp))
                with codecs.open(self.nomfichier,'a','utf-8') as file_:
                    file_.write(temp + "\n") 

        # cela n'a pas fonctionné on retourne False
        return False
    
    def checkWhois(self, url):
        # on check le Whois 
        whois_info = "Whois : ?"
        parsed_uri = urlparse(url)
        url_to_whois = '{uri.netloc}'.format(uri=parsed_uri)
        self.logMessage("WHOIS :::" + url_to_whois)
        resultat = False
        try :
            w = whois.whois(url_to_whois)
            exp_date = "?"
            if isinstance(w.expiration_date, list) :
                exp_date = w.expiration_date[0]
            else :
                exp_date = w.expiration_date
            if exp_date != None :
                whois_info = "Expiration date : " + str(exp_date)
            else :
                 whois_info = "Updated date : " + str(w.updated_date)
            resultat = True
        except Exception :
            whois_info = "Whois Unknown (need manual check)"
        return whois_info, resultat
           
    def processOneUrl(self, url, threadNumber):
        
        self.logMessage(str(threadNumber) + "  * Process One url : " + str(url))
        if url == False :
            return False
        # on met à jour l'interface
        if url not in self.queueUrls :
            self.queueUrls.put(url)
            self.maj_compteur()
            
        try:
            #print (str(threadNumber) + " (process on url) : " + str(url))
            #tr = tracker.SummaryTracker()
            html_page = self.downloadURL(url, False)
            #tr.print_diff()
        except ValueError:
            self.logMessage(" *** il y a eu un problème de dowload du HTML")
            #self.resultUrl[url] = True   # set as crawled
        
        #self.logMessage("html page + " + str(html_page))
        if html_page != False : 
            
            html = "<html></html>"
            try:
                html = lxml.html.fromstring(html_page)
            except Exception:
                self.logMessage(" -> Impossible de parser le HTML")
                self.nombreThreads -= 1
                return False
            
            html.make_links_absolute(url, resolve_base_href=True)
            
            # smart_strings : pour liberer de la mémoire quand on en a besoin
            urls = html.xpath('//a/@href', smart_strings=False)
            del html
            
            url_de_base = self.entryUrl.get()
            chaine_a_trouver = self.entrySearch.get().replace(" ", "")
            chaine_a_checker = self.entryCheck.get().replace(" ", "")
            
            #self.logMessage(" Les urls de la page : " + str(urls))
            
            for linkO in urls:
                if self.stopThread :
                    break
                linkOs = linkO.split("#")
                if len(linkOs) > 1 :
                    link = linkOs[0]
                else :
                    link = linkO
                
                #self.logMessage("link : " +str(link))
                if ( link not in self.queueUrls ) :
                    if chaine_a_trouver in link :
                        #self.logMessage("chaine a trouver " + str(chaine_a_trouver))
                        # on regarde si on l'a déjà crawlée
                        if link not in self.queueUrlsCrawled :
                            if link not in self.queueUrlsAttente :
                                self.nombreTrouve += 1
                                self.queueUrlsAttente.put(link)
                            if link not in self.queueUrls :
                                self.queueUrls.put(link)
                        #self.nombreTrouve += self.connexion.addUrl(link)
                    if chaine_a_checker in link :
                        #self.logMessage("chaine a checker " + str(chaine_a_checker))
                        # on ne crawle pas mais on check l'url
                        # le param True indique qu'on doit vérifier les codes retours
                        self.downloadURL(link, True)
            del urls
            #self.nombreThreads -= 1                                        
            #print (str(threadNumber) + " (process on url FIN) : " + str(url))
            del html_page
        
    # on trouve la prochaine url à crawler
    def moreToCrawl(self, threadNumber):
        url = None
        if not self.queueUrlsAttente.empty() :
            #url = self.toutesUrlNew[0]
            # on veut avoir une url au hasard
            #url = random.choice(self.toutesUrlNew)
            #self.toutesUrlNew.remove(url)
            url = self.queueUrlsAttente.get()
        else :
            url = None
            
        if ( url is not None ) :
            try:
                self.logMessage("(more to crawl) " + url)
                return url
            except:
                self.logMessage("erreur encodage url")
                del url
                return False 
        else :
            self.logMessage("URL VIDE !!! - moretoCrawl")
        del url
        return False

    # resume last session
    def resume(self) :
        self.restoreSession()
        self.stopThread = False
        self.fenetre.config(cursor="watch")
        
        self.nombreTrouve = 1
        self.nombreThreads = 0
        
        self.thread = threading.Thread(target=self.crawltout, args=())
        self.thread.start()

    # crawl du site (lancé depuis le bouton de l'interface)
    def crawl(self) :
        
        if askquestion("Start new session ?", "Do you want to start a new session? (all previous work will be lost, expired domains stays)") != "no":

            self.logMessage("Session started...", True);
            # on ne restaure pas la session précédente
            self.toutesUrl = []
            self.toutesUrlChecked = []
            self.toutesUrlCrawled = []
            self.toutesUrlNew = []

            self.queueUrls = MyQueue()  # toutes les urls connues
            self.queueUrlsChecked = MyQueue()  # celles qui ont été vérifiées
            self.queueUrlsCrawled = MyQueue()  # celles qui ont été crawlées
            self.queueUrlsAttente = MyQueue()  # celles qu'on doit crawler

            self.tousThreads = []
            
            # pour avoir le bon nombre de threads
            self.numberOfThreads = int(self.entryThreads.get())

            lesUrls = self.entryUrl.get().replace(" ","").split('|')
            for uneUrl in lesUrls :
                if uneUrl not in self.queueUrlsAttente :
                    self.queueUrlsAttente.put(uneUrl)
                if uneUrl not in self.queueUrls :
                    self.queueUrls.put(uneUrl)
                
            self.stopThread = False
            self.fenetre.config(cursor="watch")

            self.nombreTrouve = 1
            self.nombreThreads = 0
        
            self.thread = threading.Thread(target=self.crawltout, args=())
            self.thread.start()


    # un seul thread, on peut lancer plusieures fois cette fonction pour faire du multithread

    def crawltoutUnSeul(self, threadNumber):

        # boucle sur les urls
        while True:
            if self.stopThread:
                break
            toCrawl = self.moreToCrawl(threadNumber)
            print(toCrawl)
            if not toCrawl:
                break

            self.processOneUrl(toCrawl, threadNumber)
            self.maj_compteur()

        # fin traitement
        self.fenetre.config(cursor="")

    # rajout pour le multi-thread
    def crawltout(self):
        # self.connexion = lib_bd.connexionBase(self.base)
        # self.crawltoutUnSeul("Thread 0")
        for i in range(0, self.numberOfThreads):
            thread = threading.Thread(target=self.crawltoutUnSeul, args=(("Thread " + str(i),)))
            thread.start()
            if self.stopThread:
                break
            else:
                time.sleep(1)
        
    def stopcrawl(self) :
        # on ne fait rien si on a pas démarrer le process
        showinfo("Info", "We need to stop all threads. Please click 'OK' and wait a few minutes...")

        self.stopThread = True

        # sauvegarde de la session
        self.saveSession()

        self.logMessage("⌛ Please wait a minute before finish...", True)        
        # on termine tous les threads
        for t in self.tousThreads :
            try:
                t.join(5.00)
                self.tousThreads.remove(t)
                del t
            except Exception:
                self.logMessage("probleme stopcrawl")
        #self.thread._stop()
        #time.sleep(60)
        self.logMessage("Done ! ", True)
        
        
        # fin traitement
        try :
            self.fenetre.config(cursor="")
        except Exception :
            self.logMessage("Exception fenetre tkinter pas sur main thread")

    def maj_compteur(self) :
        nombreChecked = self.queueUrlsChecked.qsize()
        nombreCrawled = self.queueUrlsCrawled.qsize()
        nombreTrouve = self.queueUrls.qsize()
        try:
            self.label_compteur.set(str(nombreChecked) + " Checked URLs ★ " + str(nombreCrawled) + " Crawled URLs ★ " + str(nombreTrouve) + " Known URLs")
        except Exception:
            self.logMessage("pb maj compteur")
            
        del nombreChecked
        del nombreCrawled
        del nombreTrouve
            
    # boucle principale TKinter
    def runLoop(self) :
        self.fenetre.mainloop()
