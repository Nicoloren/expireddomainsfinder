# Expired Domains Finder
Finding good domains is difficult. That is why we have built this software : Expired Domains Finder. This software is free with no warranty. It may damage your computer (even if that would be very surprising and our test haven't revealed that bug). 

This sofware is no longer supported.

What this software does :

 *   Crawl websites and check for expired domains
 *   Check for errors and websites (brocken links for example)
 *   Check whois and DNS
 *   Create a great list of expired domains
 *   Get PA, DA and number of backlinks for a domain


Buttons :

    Start New : start a new session. This will clear the queue but all the expired domains already found will stay in the list.

    Resume : resume previous session.

    Stop : stop session (Warning : it may take several minutes to properly stop the tool. Please wait if you want to do a "Resume" after)

    Quit : quit

    Import URLs : import a list of urls (simple text file with an url by line)

Fields :

    URLs to crawl : the tool is a crawler, enter url(s) to crawl (separated by "|")

    Crawl URLs that contains : type of url to crawl

        Example "tumblr.com" : we will only crawls urls that contains "tumblr.com"

        We can use "." to crawl every websites

    Check URLs that contains : type of urls to check (for errors, expired domains, etc.)

        "Example ".edu" : will verify only domains that have ".edu" in their name


Parameters :

    URL ou Domain / Subdomain : if you want to check "www.mywebsite.com/myurl.html" (url) or "www.mywebsite.com" (domain). Usually we want to find expired domains, so check "Domain / subdomain".
    Expired : to find expired domains (with a check of Whois and DNS)
    404 / 403 / 500 : to find HTTP errors
    All : to find all HTTP errors

Nicolas Lorenzon - http://www.lorenzon.ovh
