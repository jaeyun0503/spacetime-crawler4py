import re
from urllib.parse import urlparse, urldefrag, urljoin, parse_qs
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from collections import defaultdict
from stopWords import STOPWORDS

word_count = defaultdict(int) # To save word counts for later (using this to skip initializing step)
subdomains = defaultdict(int) # To save url counts for each subdomain under ics.uci.edu
parsers = defaultdict(RobotFileParser) # To save instance of RobotFileParser to avoid parsing multiple times 

unique_pages = {} # Dictionary for saving the hash values and unique urls
largest_words = 0 # Saving the number of words in the longest page
largest_page = "" # Saving the url of the longest page
robot_check = False # Boolean value for creating RobotFileParsers

def scraper(url, resp):
    """
    Generates a list of valid URLs using extract_next_link() and is_valid() functions

    Args:
        url (string): URL of page
        resp (resp): Response Object

    Returns:
        list of URLs: URLs that have been checked
    """
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    """
    Generates a list of links of unique pages. Checks the response status of the url, the content of the url can be considered as high textual information content,
    and hash the content of the page to check if it matches with pages that already exist (similar content is being skipped).

    Args:
        url (string): URL of page
        resp (resp): Response Object

    Returns:
        list of URLs: URLs that have unique content
    """
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    global word_count, subdomains, unique_pages, largest_words, largest_page
    urls = set()  # Set for saving unique links

    try:        
        if resp.status == 200 and resp.raw_response.content: # Check if status is 200 (OK) and the response contains content
            soup = BeautifulSoup(resp.raw_response.content,'html.parser')
            page_content = soup.get_text()  # Getting the text on the URL page
            tokens = []  # List of tokens

            # for loop to check if the word is valid, not in stop words, then add to list of tokens and update the count
            for i in re.findall(r'\b[a-zA-Z][a-zA-Z\']*[a-zA-Z]\b', page_content):
                temp = i.lower()
                if temp not in STOPWORDS:
                    tokens.append(temp)
                    word_count[temp] += 1

            if 250 < len(tokens) < 100000000: # List of 250 < tokens < 100000000 is considered as having high textual information content
                # Checking repetitive page Portion using hash
                hashed = hash(tuple(tokens)) # Using tuple as hash() needs immutable object
                if hashed in unique_pages.keys():
                    return [] # Returning nothing since this page has already been extracted
                unique_pages[hashed] = url 

                # Subdomain Portion
                subdomain = urlparse(url).hostname # Parse the url to get the subdomain of the url
                if subdomain.endswith('.ics.uci.edu') and subdomain != "www.ics.uci.edu":
                    subdomains[subdomain] += 1 # Adding occurrence of subdomain

                # Longest Page Portion
                if len(tokens) > largest_words:
                    largest_words = len(tokens)
                    largest_page = url

                # Getting hyperlink Portion
                for j in soup.find_all('a', href=True):
                    defragmented = urldefrag(j["href"])  # Removing Fragment identifier
                    new_link = urljoin(url, defragmented.url)

                    if new_link:  # TODO: CHECK
                        urls.add(new_link)

                # Printing Portion
                print(f'URL:        {url}')
                print(f'    Length of the page:        {len(tokens)}')
                print(f'    New Links URLs added:        {len(urls)}')
                print("====================================================================")
        
        else:
            print(f"ERROR: {resp.error}")
    except:
        print("ERROR WHILE SCRAPING")

    return list(urls)


def is_valid(url):
    """
    Checks if a url is valid (meeting the requirements). Including: checking for URL scheme, domains, calendar trap, excessive query parameters, robots.txt. 

    Args:
        url (string): url of page

    Returns:
        truth value (boolean): validity of the page (whether to crawl or not)
    """
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    # global robot_check
    global parsers
    # if not robot_check:
    #     load_robots()
    #     robot_check = True

    try:
        # URL scheme check
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Domain check
        domains = ['.ics.uci.edu', '.cs.uci.edu', '.stat.uci.edu', '.informatics.uci.edu']
        if not any(domain in parsed.netloc for domain in domains):
            return False

        # Calendar trap (need to fix later)
        if re.search(r'(/calendar/|/\d{4}/\d{1,2}/\d{1,2}/)', parsed.path):
            return False

        # Excessive query parameters
        if len(parse_qs(parsed.query)) > 15:  # More than 15 -- Excessive
            return False

        # Robots.txt
        if parsed.netloc not in parsers:
            robot_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            parsers[parsed.netloc] = RobotFileParser()
            parsers[parsed.netloc].set_url(robot_url)
            try:
                parsers[parsed.netloc].read()
            except Exception as e:
                return False
        if not parsers[parsed.netloc].can_fetch("*", url):
            return False


        # File extensions
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4|mpg"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise


def load_robots():
    """
    Makes a defaultdict of RobotFileParsers

    Args:
        None

    Returns:
        None
    """
    global parsers
    domains = ["https://ics.uci.edu/robots.txt",
               "https://cs.ics.uci.edu/robots.txt",
               "https://informatics.uci.edu/robots.txt",
               "https://stat.uci.edu/robots.txt"]

    for i in domains:
        parsed = urlparse(i)
        parsers[parsed.netloc] = RobotFileParser()
        parsers[parsed.netloc].set_url(i)
        parsers[parsed.netloc].read()


def generate_report():
    """
    Generates the report.txt based on the scraped data

    Args:
        None
    Returns:
        None
    """
    sorted_words = sorted(word_count, key=word_count.get, reverse=True)[:50]

    with open("report.txt", "w") as file:
        file.write("REPORT of the Scraped Pages:\n\n")
        file.write(f"Number of Unique Pages found: {str(len(unique_pages))}\n\n")
        file.write(f"Longest Page in terms of words: {largest_page}\n")
        
        for i in range(1, 51):
            print(f"  {i}.    {sorted_words[i - 1]}\n")

        file.write(f"\nSubdomains under ics.uci.edu domain: \n")

        subdomain_list = []
        for key, value in subdomains.items():
            subdomain_list.append((key, value))
        subdomain_list.sort()

        for j in range(len(subdomain_list)):
            file.write(f'  {subdomain_list[j][0]}:  {subdomain_list[j][1]} Pages\n')
            
