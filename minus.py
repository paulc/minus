#!/usr/bin/env python

"""

    minus.py


    Introduction
    ------------

    minus.py is a Python library which interacts with the minus.com 
    (http://minus.com) file sharing service. 

    It provides three layered services:

    a)  A 'Pythonic' API to the Minus.com REST interface
    b)  An interactive Minus.com client - modeled on ftp(1)
    c)  A non-interactive command-line utility to upload/download files
        to Minus.com

    Pythonic API
    ------------

    The minus library exposes the Minus.com REST interface through a
    number of Python proxy objects:

        MinusConnection     - Low-level connection to REST API
        MinusUser           - User object 
        MinusFolder         - Folder object
        MinusFile           - File object

        MinusAPIError       - API Exception

    A simple example of interaction with the API is -

        >>> minus = MinusConnection('api_key','api_secret')        
        >>> minus.authenticate('user','password')
        >>> user = minus.activeuser() 
        >>> print [ f._name for f in user.folders() ]
        >>> folder = minus.find('Stuff')
        >>> print [ f._name for f in folder.files() ]

    (See object docstrings for methods available)

    Paging is handled transparently through the PagedList/PagedListIter
    classes - these support lazy loading however in general this is 
    not used through the helper classes.

    Interactive Client
    ------------------

    If the module is run directly the __main__ method will call an 
    interactive CLI client based on the 'cmd' library. This behaves
    in a similar way to the ftp(1) client. Basic help and command
    line editing are provided through the 'cmd' library.

    The available commands are:

        cd <folder>             Change remote folder
        del <files>..           Delete remote files
        get <remote> [<local>]  Get remote file
        lcd <path>              Change local directory
        lpwd                    Print local path
        ls                      List remote folder
        mget <files>..          Get multiple remote files
        mkdir                   Create remote folder (private)
        mkpublic                Create remote folder (public)
        mput <files>..          Put multiple local files
        put <local> [<remote>]  Put local file
        pwd                     Print remote folder
        rmdir                   Delete remote folder (deletes contents)
        stat <files>..          Print details on remote files

    The library supports local/remote globbing and local i/o rediraction - eg.

        Remote glob:        mget *.jpg (works with mget/del/ls/stat)
        Local glob:         mput *.txt (works with mput)
        Pipe to stdout:     get <file> -
        Pipe to process:    get <file> |less
        Pipe from process:  put date| date.txt

    Note - Minus.com allows multiple folders/files with the same name (the id 
    attribute provides a unique id)

    A simple example of an interactive session is:

    # ./minus.py --username <user>
    Password: 
    (Minus:user) [/] : ls
    Folder                        Updated              Files  Creator  Visibility
    --------------------------------------------------------------------------------
    Stuff                         2012-01-08 12:25:44     15  user     private
    Stuff2                        2012-01-08 13:28:04      0  user     public
    (Minus:paulc) [/] : cd Stuff
    --> CWD "Stuff" OK
    (Minus:user) [/Stuff] : ls
    Name                          Uploaded                 Size  Title
    --------------------------------------------------------------------------------
    SNV33271.jpg                  2012-01-05 18:36:22    251673  -
    SNV33183.jpg                  2012-01-05 18:35:57    176134  -
    (Minus:paulc) [/Stuff] : get SNV33271.jpg 
    --> GET "SNV33271.jpg" OK (251673 bytes)
    (Minus:user) [/Stuff] : put t1.data
    --> PUT "t1.data" OK (13672 bytes)

    Command Line Utility
    --------------------

    If the module is run from the command line with the --get, --put, or
    --list-folders options the utility runs non interactively and provides
    a simple way of uploading/downloading content - eg.

        Upload local files:     
        
            ./minus.py --user user --put 'Folder Name' <files>

            (Folder is created if it doesnt already exist)

        Upload local files to public folder:     

            ./minus.py --user user --public --put 'Folder Name' <files>

        Download remote files:

            ./minus.py --user user --get 'Folder Name' 
            
        Download matching remote files:

            ./minus.py --user user --get 'Folder Name' \*.jpg \*.png

            (Remember to quote remote glob so that it isn't expanded by the shell)

        List Folders:

            ./minus.py --user user --list-folders

        (You can specify the password on the command-line however note that this 
        will be visible in process args - if not specified will be prompted)

    API Key
    -------

    You must have a valid Minus.com API_KEY/API_SECRET to use the library (see
    http://minus.com/pages/api to request an API key). These are normally
    passed into the MinusConnection constructor.

    To use the CLI client the API_KEY/API_SECRET should be placed in a config
    file (by default ~/.minus.conf - can be changed using the --config flag).
    The file is in '.ini' format and contains a single [api] section with
    api_key and api_secret keys:

        [api]
        api_key: ...
        api_secret: ...

    Debugging/Development
    ---------------------

    You can turn on the --debug flag to see the HTTP requests/responses and also
    use the --shell flag to drop into an interactive Python interpreter immediately
    after authentication where you can experiment with the API - there will be 
    MinusConnection (minus) and MinusUser (user) variables available.

    Dependencies
    ------------

    The module comprises a single file and can be either installed normally using
    pip/site-packages etc or just installed & called from a local directory. There
    are no dependencies other than the Python interpreter (tested with 2.7 but 
    should be ok with earlier).

    Repository/Issues
    -----------------
    
    The master repository is https://bitbucket.org/paulc/minus. Please use the
    Issue tracker there to raise any issues.

    License
    -------

    MIT

    Author
    ------

    Paul Chakravarti (paul.chakravarti@gmail.com)

"""

import cmd,cookielib,fnmatch,glob,json,mimetools,mimetypes,optparse,os,\
       shlex,sys,time,types,urllib,urllib2

VERSION = '1.1'

DEFAULT_SCOPE = 'read_public read_all upload_new modify_all modify_user'

class MinusAPIError(Exception): 
    """
        API Exception Object
    """
    pass

class MinusConnection(object):

    """
        Low level connection to Minus.com REST API. Handles access token
        automatically.

        Used primarily for authentication and to retreive the 'activeuser'
        MinusUser object
    """

    API_URL = "https://minus.com/api/v2/"
    AUTH_URL = "https://minus.com/oauth/token"

    def __init__(self,api_key,api_secret,debug=False,force_https=True):
        """
            Create MinusConnection object. 

            @api_key        - Minus.com API key
            @api_secret     - Minus.com API secret
            @debug          - Turn on urllib2 debugging (HTTP request/response)
            @force_https    - Rewrite REST URIs to force HTTPS (usually only
                            authentication under HTTPS)
        """
        self.cj = cookielib.CookieJar()
        self.opener = urllib2.build_opener(
                            urllib2.HTTPSHandler(debuglevel=debug),
                            urllib2.HTTPCookieProcessor(self.cj)
                      )
        self.api_key = api_key
        self.api_secret = api_secret
        self.scope = None
        self.access_token = None
        self.refresh_token = None
        self.expires = 0
        self.force_https = force_https

    def authenticate(self,username,password,scope=DEFAULT_SCOPE):
        """
            Authenticate user

            @username       - Minus.com username
            @password       - Minus.com passowrd
            @scope          - Minus.com scope (see REST API docs) - defaults
                            to all permissions
        """
        form = { 'grant_type'    : 'password',
                 'scope'         : scope,
                 'client_id'     : self.api_key,
                 'client_secret' : self.api_secret,
                 'username'      : username,
                 'password'      : password }
        data = urllib.urlencode(form)
        try:
            response = self.opener.open(self.AUTH_URL,data).read()
            tokens = json.loads(response)
            self.access_token = tokens['access_token']
            self.refresh_token = tokens['refresh_token']
            self.scope = tokens['scope']
            self.expires = int(time.time()) + tokens['expire_in']
        except urllib2.HTTPError:
            raise MinusAPIError('Error Authenticating')

    def refresh(self,scope=None):
        """
            Refresh logon session (potentially changing scope)

            @scope          - Minus.com scope (see REST API docs)

            TODO - the request method should check the time remaining
                   on the logon session and automatically call refresh
                   if needed
        """
        form = { 'grant_type'    : 'refresh_token',
                 'scope'         : scope or self.scope,
                 'client_id'     : self.api_key,
                 'client_secret' : self.api_secret,
                 'refresh_token' : self.refresh_token }
        data = urllib.urlencode(form)
        try:
            response = self.opener.open(self.AUTH_URL,data).read()
            tokens = json.loads(response)
            self.access_token = tokens['access_token']
            self.refresh_token = tokens['refresh_token']
            self.expires = int(time.time()) + tokens['expire_in']
        except urllib2.HTTPError:
            raise MinusAPIError('Error Authenticating')

    def activeuser(self):
        """
            Return MinusUser object representing the 'activeuser' (user
            who logged on to API
        """
        return MinusUser(self,'activeuser')

    def _url(self,url):
        """
            Rewrite url add API_URL to relative paths and force https if 
            required (self.force_https is set)

            @url        - API URL to rewrite (either absolute or relative)
        """
        if url.startswith('http:') and self.force_https:
            return 'https:' + url[5:]
        elif not url.startswith('http'):
            return self.API_URL + url
        else:
            return url

    def request(self,url,data=None,method=None,content_type=None):
        """
            Send request to API and return file object with response. 
            Handles authorisation token transparently.

            @url            - API URL (absolute or relative)
            @data           - POST data
            @method         - HTTP Method
            @content_type   - HTTP Content-Type
        """
        if self.access_token is None:
            raise MinusAPIError('Not Authenticated')
        try:
            r = urllib2.Request(self._url(url),data)
            r.add_header('Authorization','Bearer %s' % self.access_token)
            if content_type:
                r.add_header('Content-Type',content_type)
            if method:
                r.get_method = lambda : method
            return self.opener.open(r)
        except urllib2.HTTPError,e:
             raise MinusAPIError('Request HTTP Error: %d' % e.code)

    def upload(self,url,content_type,body):
        """
            Send multipart/form-data upload request

            @url            - API URL (absolute or relative)
            @content_type   - multipart/form-data boundary=xxxxxx
            @body           - Data (multipart enocoded)
        """
        if self.access_token is None:
            raise MinusAPIError('Not Authenticated')
        r = urllib2.Request(self._url(url),body)
        r.add_header('Authorization','Bearer %s' % self.access_token)
        r.add_header('Content-Type', content_type)
        r.add_header('Content-Length', str(len(body)))
        return self.opener.open(r)

    def list(self,url):
        """
            Return PagedList for url
        """
        return PagedList(self,url)

    def __str__(self):
        if self.access_token:
            return '<MinusConnection: Authenticated [%s]>' % self.scope
        else:
            return '<MinusConnection: Not Authenticated>'

class MinusUser(object):

    """
        Represents Minus user & provides methods to create/find 
        associated folders
    """
    PARAMS = [ 'username', 'display_name', 'description', 'email', 'slug',
               'fb_profile_link', 'fb_username', 'twitter_screen_name',
               'visits', 'karma', 'shared', 'folders', 'url', 'avatar',
               'storage_used', 'storage_quota' ]

    def __init__(self,api,url,params=None):
        """
            Create MinusUser object - can be craeted from either a 
            url or a dict of params (typically returned by another
            API call)

            @api            - MinusConnection object
            @url            - URL for User (None if creating from params)
            @params         - Dict of user params (see PARAMS for keys)

            PARAMS list is used to create instance variables (keys are
            munged to prepend _ - ie. username is obj._username)
        """
        self.api = api
        if url:
            response = self.api.request(url)
            params = json.loads(response.read())
        for p in self.PARAMS:
            try:
                setattr(self, "_" + p, params[p])
            except KeyError:
                if p in ['email','storage_used','storage_quota']:
                    pass
                else:
                    raise MinusAPIError("Invalid User Object")

    def folders(self):
        """
            Return list of MinusFolder objects associated with user
        """
        return [ MinusFolder(self.api,None,f) 
                    for f in self.api.list(self._folders) ]

    def new_folder(self,name,public=False):
        """
            Create new folder and return MinusFolder object

            @name           - Folder name
            @public         - Make folder public (True/False)
        """
        form = { 'name' : name,
                 'is_public' : public and 'true' or 'false' }
        data = urllib.urlencode(form)
        r = self.api.request(self._folders,data)
        return MinusFolder(self.api,None,json.loads(r.read()))

    def find(self,name):
        """
            Return MinusFolder object with specified name (or None)

            @name           - Folder name

            (Note - if there are multiple folders which match the
            name the first match is returned)
        """
        for f in self.api.list(self._folders):
            if f['name'] == name:
                return MinusFolder(self.api,None,f)
        return None

    def glob(self,pattern):
        """
            Return list of MinusFolder objects matching glob 
            pattern

            @pattern        - Folder glob pattern
        """
        result = []
        for f in self.api.list(self._folders):
            if fnmatch.fnmatch(f['name'],pattern):
                result.append(MinusFolder(self.api,None,f))
        return result

    def followers(self):
        """
            Return list of followers
        """
        return [ MinusUser(self.api,None,u) 
                    for u in self.api.list("users/%s/followers" % self._slug) ]

    def following(self):
        """
            Return following list
        """
        return [ MinusUser(self.api,None,u) 
                    for u in self.api.list("users/%s/following" % self._slug) ]

    def follow(self,user):
        """
            Follow user

            @user       - User to follow (either MinusUser object or username as string
        """
        if isinstance(user,MinusUser):
            form = { 'slug' : user._slug }
        else:
            form = { 'slug' : user }
        data = urllib.urlencode(form)
        r = self.api.request("users/%s/following" % self._slug,data)
        return MinusUser(self.api,None,json.loads(r.read()))

    def __str__(self):
        try:
            return '<MinusUser: username="%s", folders="%s", url="%s" slug="%s" storage=%d/%d>' % \
                        (self._username, self._folders, self._url, self._slug, 
                                    self._storage_used, self._storage_quota)
        except AttributeError:
            return '<MinusUser: username="%s", folders="%s", url="%s" slug="%s">' % \
                        (self._username, self._folders, self._url, self._slug)

class MinusFolder(object):

    """
        Represents Minus folder object & provides methods to create/find files
    """
    PARAMS = [ 'files', 'view_count', 'date_last_updated', 'name', 'creator', 
               'url', 'thumbnail_url', 'file_count', 'is_public', 'id' ]

    def __init__(self,api,url,params=None):
        """
            Create MinusFolder object - can be craeted from either a 
            url or a dict of params (typically returned by another
            API call)

            @api            - MinusConnection object
            @url            - URL for Folder (None if creating from params)
            @params         - Dict of user params (see PARAMS for keys)

            PARAMS list is used to create instance variables (keys are
            munged to prepend _ - ie. name is obj._name)
        """
        self.api = api
        if url:
            response = self.api.request(url)
            params = json.loads(response.read())
        for p in self.PARAMS:
            setattr(self, "_" + p, params[p])

    def files(self):
        """
            Return list of MinusFile objects in folder
        """
        return [ MinusFile(self.api,None,f) for f in self.api.list(self._files) ]
        
    def find(self,name):
        """
            Return MinusFile object with specified name (or None)

            @name           - File name

            (Note - if there are multiple files which match the
            name the first match is returned)
        """
        for f in self.api.list(self._files):
            if f['name'] == name:
                return MinusFile(self.api,None,f)
        return None

    def glob(self,pattern):
        """
            Return list of MinusFile objects matching glob 
            pattern

            @pattern        - File glob pattern
        """
        result = []
        for f in self.api.list(self._files):
            if fnmatch.fnmatch(f['name'],pattern):
                result.append(MinusFile(self.api,None,f))
        return result

    def new(self,filename,data,caption=None,mimetype=None):
        """
            Create remote file 

            @filename       - Remote filename
            @data           - Data
            @caption        - Caption (optional)
            @mimetype       - Mimetype (optional)

            XXX - data is stored in memory so this isnt 
            useful for very large files
        """
        fields = [('filename',filename),('caption',caption)]
        files = [('file',filename,data)]
        content_type,body = encode_multipart_formdata(fields,files,mimetype)
        r = self.api.upload(str(self._files),content_type,body)
        return MinusFile(self.api,None,json.loads(r.read()))

    def delete(self):
        """
            Delete folder
        """
        self.api.request(self._url,None,'DELETE')

    def __str__(self):
        return '<MinusFolder: name="%s" id="%s" url="%s" files="%s" files=%d public=%s>' % \
                (self._name, self._id, self._url, self._files, 
                        self._file_count, self._is_public)

class MinusFile(object):

    """
        Represents Minus file
    """

    PARAMS = [ 'id', 'name', 'title', 'caption', 'width', 'height', 'filesize', 
               'mimetype', 'folder', 'url', 'uploaded', 'url_rawfile', 
               'url_thumbnail' ]

    def __init__(self,api,url,params=None):
        """
            Create MinusFile object - can be craeted from either a 
            url or a dict of params (typically returned by another
            API call)

            @api            - MinusConnection object
            @url            - URL for File (None if creating from params)
            @params         - Dict of user params (see PARAMS for keys)

            PARAMS list is used to create instance variables (keys are
            munged to prepend _ - ie. name is obj._name)
        """
        self.api = api
        if url:
            response = self.api.request(url)
            params = json.loads(response.read())
        for p in self.PARAMS:
            setattr(self, "_" + p, params[p])

    def file(self):
        """
            Return file object for remote file
        """
        return self.api.request(self._url_rawfile)

    def data(self):
        """
            Return string object for remote data
        """
        return self.file().read()

    def delete(self):
        """
            Delete remote file
        """
        self.api.request(self._url,None,'DELETE')

    def __str__(self):
        return '<MinusFile: name="%s" title="%s" caption="%s" id="%s" url="%s" size=%d>' % \
                (self._name, self._title, self._caption, self._id, 
                        self._url, self._filesize)

class PagedList(object):

    """
        Object encapsulating remote paged list
    """
    def __init__(self,api,url):
        """
            Create PagedList object

            @api            - MinusConnection object
            @url            - Remote URL 
        """
        self.api = api
        response = api.request(url).read()
        params = json.loads(response)
        self._total = params['total']
        self._next = params['next']
        self._results = params['results']

    def extend(self):
        """
            Get next page
        """
        if self._next:
            response = self.api.request(self._next).read()
            params = json.loads(response)
            self._next = params['next']
            self._results.extend(params['results'])
            return True
        return False

    def __iter__(self):
        """
            Return iterator object
        """
        return PagedListIter(self)

class PagedListIter(object):

    """
        Iterator object supporting PagedList
    """

    def __init__(self,pagedlist):
        """
            Create iterator

            @pagedlist          - PagedList object
        """
        self.list = pagedlist
        self.index = 0

    def next(self):
        """
            Get next item transparently extending series as required
        """
        try:
            result = self.list._results[self.index]
        except IndexError:
            if self.list.extend():
                result = self.list._results[self.index]
            else:
                raise StopIteration
        self.index += 1
        return result

def wrap_api_error(f):
    """
        Wrapper to catch remote API errors in CLI
    """
    def wrapped(self,*args):
        try:
            result = f(self,*args)
        except MinusAPIError,e:
            print "ERROR: API Command Failed (%s)" % e.message
    return wrapped

def root_only(f):
    """
        Wrapper to force CLI commands to root level only
    """
    def wrapped(self,*args):
        if self.folder:
            print "ERROR: Command only valid at root folder"
        else:
            result = f(self,*args)
            return result
    return wrapped

def folder_only(f):
    """
        Wrapper to force CLI commands to folder only
    """
    def wrapped(self,*args):
        if not self.folder:
            print "ERROR: Command only valid in sub-folder"
        else:
            return f(self,*args)
    return wrapped

class MinusCLI(cmd.Cmd):

    """
        Cmd based CLI for Minus.com modeled on ftp(1)
    """

    def connect(self,user):
        """
            Connect to service

            @user       - Authenticated MinusUser object
        """
        self.user = user
        self.root = user._folders
        self.folder = None
        self._set_prompt()

    def _set_prompt(self):
        """
            Set interactive prompt to show user/folder
        """
        self.prompt = "(Minus:%s) [/%s] : " % (self.user._username, 
                                    self.folder and self.folder._name or "")

    def do_pwd(self,line):
        """
            Print remote folder
        """
        if self.folder:
            print "Folder:", self.folder._name
        else:
            print "Folder: /"

    def do_lpwd(self,line):
        """
            Print local path
        """
        print "Local Path:", os.getcwd()

    def do_lcd(self,line):
        """
            Change local directory 
        """
        args = shlex.split(line)
        path = args[0]
        try:
            os.chdir(path)
            print "Local Path:", os.getcwd()
        except OSError:
            print "ERROR: Unable to chdir to \"%s\"" % path

    def do_cd(self,line):
        """
            Change remote folder
        """
        args = shlex.split(line)
        folder = args[0]
        if self.folder:
            if folder == "..":
                self.folder = None
            else:
                if folder.startswith("../"):
                    self.folder = None
                    folder = folder[3:]
                self._cd(folder)
        else:
            self._cd(args[0])
        self._set_prompt()

    @root_only
    @wrap_api_error
    def _cd(self,folder):
        new = self.user.find(folder)
        if new:
            self.folder = new
            print "--> CWD \"%s\" OK" % folder
        else:
            print "--> CWD \"%s\" FAILED" % folder
        
    @folder_only
    @wrap_api_error
    def do_stat(self,line):
        """
            Print details on remote files (supports remote glob argument)
        """
        files = {}
        for pattern in shlex.split(line):
            for remote in self.folder.glob(pattern):
                files[remote._id] = remote
        if files:
            for f in files.values():
                print "--> STAT \"%s\"" % f._name
                print
                print "    Id          :", f._id
                print "    Name        :", f._name
                print "    Title       :", f._title
                print "    Caption     :", f._caption
                print "    Filesize    :", f._filesize
                print "    MIME Type   :", f._mimetype
                print "    Uploaded    :", f._uploaded
                print "    URL         :", f._url
                print "    URL (Raw)   :", f._url_rawfile
                print "    URL (Thumb) :", f._url_thumbnail
                print
        else:
            print "--> STAT - No files match"

    @root_only
    @wrap_api_error
    def do_mkpublic(self,line):
        """
            Create remote folder (public)
        """
        for d in shlex.split(line):
            new = self.user.new_folder(d,True)
            print "--> MKPUBLIC \"%s\" OK" % new._name

    @root_only
    @wrap_api_error
    def do_mkdir(self,line):
        """
            Create remote folder (private))
        """
        for d in shlex.split(line):
            new = self.user.new_folder(d)
            print "--> MKDIR \"%s\" OK" % new._name

    @root_only
    @wrap_api_error
    def do_rmdir(self,line):
        """
            Delete remote folders
        """
        for d in shlex.split(line):
            folder = self.user.find(d)
            if folder:
                folder.delete()
                print "--> RMDIR \"%s\" OK" % d
            else:
                print "--> RMDIR \"%s\" FAILED (No such folder)" % d

    @folder_only
    @wrap_api_error
    def do_del(self,line):
        """
            Delete remote files
        """
        matches = 0
        for pattern in shlex.split(line):
            for remote in self.folder.glob(pattern):
                matches += 1
                remote.delete()
                print "--> DEL \"%s\" OK" % remote._name
        if matches == 0:
                print "--> DEL FAILED (No files match)" 

    @folder_only
    @wrap_api_error
    def do_put(self,line):
        """
            Put local file

            put <local> [<remote>]

            <local> supports i/o redirection (- for stdin, cmd| for pipe)
        """
        args = shlex.split(line)
        if args:
            try:
                local = args[0]
                if local.endswith("|"):
                    f = self._pipe_read(local[:-1])
                else:
                    f = open(local)
                if len(args) > 1: 
                    remote = args[1]
                else:
                    remote = args[0]
                data = f.read()
                f.close()
                new = self.folder.new(remote,data)
                print "--> PUT \"%s\" OK (%d bytes)" % (new._name,len(data))
            except IOError,e:
                print "--> PUT \"%s\" FAILED (Error opening local file: %s)" % (
                                local,args[0])

    @folder_only
    @wrap_api_error
    def do_get(self,line):
        """
            Get remote file

            get <remote> [<local>]

            <local> supports i/o redirection (- for stdin, |cmd for pipe)
        """
        if self.folder:
            args = shlex.split(line)
            if args:
                rname = args[0]
                remote = self.folder.find(rname)
                if remote:
                    if len(args) > 1: 
                        local = args[1]
                    else:
                        local = args[0]
                    data = remote.data()
                    if local is "-":
                        if data.endswith("\n"):
                            print data,
                        else:
                            print data
                    elif local.startswith("|"):
                        self._pipe_write(local[1:],data)
                    else:
                        try:
                            open(local,"w").write(data)
                            print "--> GET \"%s\" OK (%d bytes)" % (
                                            remote._name,len(data))
                        except IOError:
                            print "--> GET \"%s\" FAILED (Can't write local file)" % remote._name
                else:
                    print "--> GET \"%s\" FAILED (No such file)" % rname
        else:
            print "Error - Must be in folder"

    @folder_only
    @wrap_api_error
    def do_mput(self,line):
        """
            Put multiple local files

            mput <files>..

            Supports local globbing
        """
        files = set()
        for pattern in shlex.split(line):
            files.update(glob.glob(pattern))
        if files:
            for f in files:
                if os.path.isfile(f):
                    try:
                        local = open(f)
                        data = local.read()
                        local.close()
                        new = self.folder.new(os.path.basename(f),data)
                        print "--> MPUT \"%s\" OK (%d bytes)" % (f,len(data))
                    except IOError:
                        print "--> MPUT \"%s\" FAILED (Error opening local file)" % f
        else:
            print "--> MPUT FAILED (No files match)"

    @folder_only
    @wrap_api_error
    def do_mget(self,line):
        """
            Get multiple remote files

            mget <files>..

            Supports remote globbing
        """
        files = {}
        for pattern in shlex.split(line):
            for f in self.folder.glob(pattern):
                files[f._name] = f
        if files:
            for name,remote in files.items():
                try:
                    data = remote.data()
                    open(name,"w").write(data)
                    print "--> MGET \"%s\" OK (%d bytes)" % (name,len(data))
                except IOError:
                    print "--> MGET \"%s\" FAILED (Can't write local file)" % name
        else:
            print "--> MGET FAILED (No files match)"

    @wrap_api_error
    def do_ls(self,line):
        """
            List remote folder
        """
        args = shlex.split(line)
        result = {}
        if not args:
            args = ['*']
        for pattern in args:
            if self.folder:
                for f in self.folder.glob(pattern):
                    result[f._id] = f
            else:
                for f in self.user.glob(pattern):
                    result[f._id] = f
        if self.folder:
            self._print_file_list(result.values())
        else:
            self._print_folder_list(result.values())

    def do_EOF(self,line):
        return True

    def _print_file_list(self,files):
        """
            Template for file listing
        """
        print "%-28s  %-19s  %8s  %s" % ("Name","Uploaded","Size","Title")
        print "-" * 80
        for f in files:
            print "%-28s  %-19s  %8d  %s" % (f._name,
                                             f._uploaded, 
                                             f._filesize,
                                             f._title or "-")

    def _print_folder_list(self,folders):
        """
            Template for folder listing
        """
        print "%-28s  %-19s  %5s  %7s  %s" % (
                        "Folder","Updated","Files","Creator","Visibility")
        print "-" * 80
        for f in folders:
            print "%-28s  %-19s  %5d  %-7s  %s" % (f._name,
                                                   f._date_last_updated,
                                                   f._file_count,
                                                   f._creator.split('/')[-1],
                                                   f._is_public and "public" 
                                                                or "private")

    def _pipe_write(self,cmd,data):
        """
            Pipe helper
        """
        try:
            pipe = os.popen(cmd,'w')
            pipe.write(data)
            pipe.close()
        except IOError:
            pass
    
    def _pipe_read(self,cmd):
        """
            Pipe helper
        """
        try:
            return os.popen(cmd)
        except IOError:
            pass

def encode_multipart_formdata(fields,files,mimetype=None):
    """
    Derived from - http://code.activestate.com/recipes/146306/

    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be 
    uploaded as files

    Returns (content_type, body) ready for httplib.HTTP instance
    """

    BOUNDARY = mimetools.choose_boundary()
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (
                        key, filename))
        L.append('Content-Type: %s' % (mimetype or 
                                       mimetypes.guess_type(filename)[0] or 
                                       'application/octet-stream'))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(map(bytes,L))
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

if __name__ == '__main__':

    def get(user,folder,args):
        remote = user.find(folder)
        if not remote:
            print "ERROR: Can't open remote folder \"%s\"" % folder
        else:
            files = {}
            if not args:
                args = ['*']
            for pattern in args:
                for f in remote.glob(pattern):
                    files[f._name] = f
            if files:
                for name,remote in files.items():
                    try:
                        data = remote.data()
                        open(name,"w").write(data)
                        print "--> GET \"%s\" OK (%d bytes)" % (name,len(data))
                    except IOError,e:
                        print "ERROR: Unable to download \"%s\" (%s)" % (
                                    f,e.strerror) 
                    except MinusAPIError,e:
                        print "ERROR: MinusAPIError \"%s\" (%s)" % (f,e.message) 
            else:
                print "ERROR: No remote files match"

    def put(user,folder,public,args):
        remote = user.find(folder)
        if not remote:
            remote = user.new_folder(folder,public)
        for f in args:
            try:
                local = open(f)
                data = local.read()
                remote.new(os.path.basename(f),data)
                local.close()
                print "--> PUT \"%s\" OK (%d bytes)" % (f,len(data))
            except IOError,e:
                print "ERROR: Unable to upload \"%s\" (%s)" % (f,e.strerror) 
            except MinusAPIError,e:
                print "ERROR: MinusAPIError \"%s\" (%s)" % (f,e.message) 

    def list_folders(user):
        for f in user.folders():
            print "%s (%d files)%s" % (f._name,f._file_count,
                                       f._is_public and " PUBLIC" or "")

    import os.path,optparse,getpass,ConfigParser

    parser = optparse.OptionParser(usage="Usage: %prog [options] <args>")
    parser.add_option("--username",
                        help="Minus.com username (required)")
    parser.add_option("--password",
                        help="Minus.com password")
    parser.add_option("--config",
                        help="API configuration file",default="~/.minus.conf")
    parser.add_option("--list-folders",action="store_true",
                        help="List remote folders")
    parser.add_option("--put",metavar="FOLDER",
                        help="Upload files to folder (created if doesnt exist)")
    parser.add_option("--get",metavar="FOLDER",
                        help="Download files matching args (glob) from folder (full folder if no args)")
    parser.add_option("--public",action="store_true",
                        help="Create public folder (with --put)")
    parser.add_option("--debug",action="store_true",
                        help="Debug HTTP requests")
    parser.add_option("--force-https",action="store_true",
                        help="Force HTTPS for all transactions (normally authentication only)")
    parser.add_option("--shell",action="store_true",
                        help="Drop into python interpreter")
    options,args = parser.parse_args()

    if options.username is None:
        parser.print_help()
        sys.exit()
    if options.password is None:
        options.password = getpass.getpass("Minus.com Password: ")

    config = ConfigParser.ConfigParser()

    try:
        config.read(os.path.expanduser(options.config))
        api_key = config.get('api','api_key')
        api_secret = config.get('api','api_secret')

        minus = MinusConnection(api_key,api_secret,options.debug,options.force_https)
        minus.authenticate(options.username,options.password)
        user = minus.activeuser()

        if options.shell:
            import code
            code.interact(local=locals())
        else:
            cli = MinusCLI()
            cli.connect(user)
            if options.list_folders:
                list_folders(user)
            elif options.put:
                put(user,options.put,options.public,args)
            elif options.get:
                get(user,options.get,args)
            else:
                cli.cmdloop()

    except (ConfigParser.NoSectionError,ConfigParser.NoOptionError):
        print "Invalid Minus.com API configuration file:",options.config


