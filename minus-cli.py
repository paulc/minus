
import cmd,cookielib,fnmatch,json,mimetools,mimetypes,optparse,os,shlex,sys,time,types,urllib,urllib2

class MinusAPIError(Exception): pass

class MinusAPI(object):

    API_KEY = "497d2fb4eb5a7b38cb1302f78e95da"
    API_SECRET = "1cab9be1c76c61d2ed396a4baaf127"
    API_URL = "https://minus.com/api/v2/"
    AUTH_URL = "https://minus.com/oauth/token"

    def __init__(self,debug=False,force_https=True):
        self.cj = cookielib.CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPSHandler(debuglevel=debug),
                                           urllib2.HTTPCookieProcessor(self.cj))
        self.scope = None
        self.access_token = None
        self.refresh_token = None
        self.expires = 0
        self.force_https = True

    def authenticate(self,username,password,scope='read_public'):
        form = { 'grant_type'    : 'password',
                 'scope'         : scope,
                 'client_id'     : self.API_KEY,
                 'client_secret' : self.API_SECRET,
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
        form = { 'grant_type'    : 'refresh_token',
                 'scope'         : scope or self.scope,
                 'client_id'     : self.API_KEY,
                 'client_secret' : self.API_SECRET,
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
        return MinusUser(self,'activeuser')

    def _url(self,url):
        if url.startswith('http:') and self.force_https:
            return 'https:' + url[5:]
        elif not url.startswith('http'):
            return self.API_URL + url
        else:
            return url

    def request(self,url,data=None,method=None,content_type=None):
        if self.access_token is None:
            raise MinusAPIError('Not Authenticated')
        r = urllib2.Request(self._url(url),data)
        r.add_header('Authorization','Bearer %s' % self.access_token)
        if content_type:
            r.add_header('Content-Type',content_type)
        if method:
            r.get_method = lambda : method
        return self.opener.open(r)

    def upload(self,url,content_type,body):
        if self.access_token is None:
            raise MinusAPIError('Not Authenticated')
        r = urllib2.Request(self._url(url),body)
        r.add_header('Authorization','Bearer %s' % self.access_token)
        r.add_header('Content-Type', content_type)
        r.add_header('Content-Length', str(len(body)))
        return self.opener.open(r)

    def list(self,url):
        return PagedList(self,url)

    def __str__(self):
        if self.access_token:
            return '<MinusAPI: Authenticated [%s]>' % self.scope
        else:
            return '<MinusAPI: Not Authenticated>'

class MinusUser(object):

    PARAMS = [ 'username', 'display_name', 'description', 'email', 'slug',
               'fb_profile_link', 'fb_username', 'twitter_screen_name',
               'visits', 'karma', 'shared', 'folders', 'url', 'avatar',
               'storage_used', 'storage_quota' ]

    def __init__(self,api,url,params=None):
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
        return [ MinusFolder(self.api,None,f) for f in self.api.list(self._folders) ]

    def new_folder(self,name,public=False):
        form = { 'name' : name,
                 'is_public' : public and 'true' or 'false' }
        data = urllib.urlencode(form)
        r = self.api.request(self._folders,data)
        return MinusFolder(self.api,None,json.loads(r.read()))

    def find(self,name):
        for f in self.api.list(self._folders):
            if f['name'] == name:
                return MinusFolder(self.api,None,f)
        return None

    def glob(self,pattern):
        result = []
        for f in self.api.list(self._folders):
            if fnmatch.fnmatch(f['name'],pattern):
                result.append(MinusFolder(self.api,None,f))
        return result

    def followers(self):
        return [ MinusUser(self.api,None,u) for u in self.api.list("users/%s/followers" % self._slug) ]

    def following(self):
        return [ MinusUser(self.api,None,u) for u in self.api.list("users/%s/following" % self._slug) ]

    def follow(self,user):
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

    PARAMS = [ 'files', 'view_count', 'date_last_updated', 'name', 'creator', 'url',
               'thumbnail_url', 'file_count', 'is_public', 'id' ]

    def __init__(self,api,url,params=None):
        self.api = api
        if url:
            response = self.api.request(url)
            params = json.loads(response.read())
        for p in self.PARAMS:
            setattr(self, "_" + p, params[p])

    def files(self):
        return [ MinusFile(self.api,None,f) for f in self.api.list(self._files) ]
        
    def find(self,name):
        for f in self.api.list(self._files):
            if f['name'] == name:
                return MinusFile(self.api,None,f)
        return None

    def glob(self,pattern):
        result = []
        for f in self.api.list(self._files):
            if fnmatch.fnmatch(f['name'],pattern):
                result.append(MinusFile(self.api,None,f))
        return result

    def new(self,filename,data,caption=None,mimetype=None):
        fields = [('filename',filename),('caption',caption)]
        files = [('file',filename,data)]
        content_type,body = encode_multipart_formdata(fields,files,mimetype)
        r = self.api.upload(self._files,content_type,body)
        return MinusFile(self.api,None,json.loads(r.read()))

    def delete(self):
        self.api.request(self._url,None,'DELETE')

    def __str__(self):
        return '<MinusFolder: name="%s" id="%s" url="%s" files="%s" files=%d public=%s>' % \
                (self._name, self._id, self._url, self._files, self._file_count, self._is_public)

class MinusFile(object):

    PARAMS = [ 'id', 'name', 'title', 'caption', 'width', 'height', 'filesize', 
               'mimetype', 'folder', 'url', 'uploaded', 'url_rawfile', 'url_thumbnail' ]

    def __init__(self,api,url,params=None):
        self.api = api
        if url:
            response = self.api.request(url)
            params = json.loads(response.read())
        for p in self.PARAMS:
            setattr(self, "_" + p, params[p])

    def file(self):
        return self.api.request(self._url_rawfile)

    def data(self):
        return self.file().read()

    def delete(self):
        self.api.request(self._url,None,'DELETE')

    def __str__(self):
        return '<MinusFile: name="%s" title="%s" caption="%s" id="%s" url="%s" size=%d>' % \
                (self._name, self._title, self._caption, self._id, self._url, self._filesize)

class PagedList(object):

    def __init__(self,api,url):
        self.api = api
        response = api.request(url).read()
        params = json.loads(response)
        self._total = params['total']
        self._next = params['next']
        self._results = params['results']

    def extend(self):
        if self._next:
            response = self.api.request(self._next).read()
            params = json.loads(response)
            self._next = params['next']
            self._results.extend(params['results'])
            return True
        return False

    def __iter__(self):
        return PagedListIter(self)

class PagedListIter(object):

    def __init__(self,pagedlist):
        self.list = pagedlist
        self.index = 0

    def next(self):
        try:
            result = self.list._results[self.index]
        except IndexError:
            if self.list.extend():
                result = self.list._results[self.index]
            else:
                raise StopIteration
        self.index += 1
        return result

class MinusCLI(cmd.Cmd):

    def connect(self,user):
        self.user = user
        self.root = user._folders
        self.folder = None
        self._set_prompt()

    def _set_prompt(self):
        self.prompt = "(Minus:%s) [/%s] : " % (self.user._username, 
                                    self.folder and self.folder._name or "")

    def do_pwd(self,line):
        if self.folder:
            print "Folder:", self.folder._name
        else:
            print "Folder: /"

    def do_cd(self,line):
        args = shlex.split(line)
        if args:
            new = self.user.find(args[0])
            if new:
                self.folder = new
                print "--> CWD \"%s\" OK" % args[0]
            else:
                print "--> CWD \"%s\" FAILED" % args[0]
        else:
            self.folder = None
        self._set_prompt()

    def do_mkpublic(self,line):
        for d in shlex.split(line):
            new = self.user.new_folder(d,True)
            print "--> MKPUBLIC \"%s\" OK" % new._name

    def do_mkdir(self,line):
        for d in shlex.split(line):
            new = self.user.new_folder(d)
            print "--> MKDIR \"%s\" OK" % new._name

    def _pipe_write(self,cmd,data):
        try:
            pipe = os.popen(cmd,'w')
            pipe.write(data)
            pipe.close()
        except IOError:
            pass
    
    def _pipe_read(self,cmd):
        try:
            return os.popen(cmd)
        except IOError:
            pass

    def do_put(self,line):
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
                new = self.folder.new(remote,data)
                print "--> PUT \"%s\" OK (%d bytes)" % (new._name,len(data))
            except IOError,e:
                print "Error opening local file: %s" % args[0]

    def do_get(self,line):
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
                            f = open(local,"w").write(data)
                            print "--> GET \"%s\" OK (%d bytes)" % (remote._name,len(data))
                        except IOError:
                            print "--> GET \"%s\" FAILED (Can't write local file)" % remote
                else:
                    print "--> GET \"%s\" FAILED (No such file)" % rname
        else:
            print "Error - Must be in folder"

    def do_glob(self,line):
        args = shlex.split(line)
        if args:
            pattern = args[0]
        else:
            pattern = '*'
        if self.folder:
            self._print_file_list(self.folder.glob(pattern))
        else:
            self._print_folder_list(self.user.glob(pattern))

    def do_rm(self,line):
        args = shlex.split(line)
        if args:
            rname = args[0]
            if self.folder:
                remote = self.folder.find(rname)
            else:
                remote = self.user.find(rname)

            if remote:
                remote.delete()
                print "--> DEL \"%s\" OK" % remote._name
            else:
                print "--> DEL \"%s\" FAILED (No such file/folder)" % rname
        else:
            print "Usage: rm <file|folder>"

    def do_ls(self,line):
        if self.folder:
            self._print_file_list(self.folder.files())
        else:
            self._print_folder_list(self.user.folders())

    def _print_file_list(self,files):
        print "%-28s  %-19s  %8s  %s" % ("Name","Uploaded","Size","Title")
        print "-" * 80
        for f in files:
            print "%-28s  %-19s  %8d  %s" % (f._name,
                                             f._uploaded, 
                                             f._filesize,
                                             f._title or "-")

    def _print_folder_list(self,folders):
        print "%-28s  %-19s  %5s  %7s  %s" % ("Folder","Updated","Files","Creator","Visibility")
        print "-" * 80
        for f in folders:
            print "%-28s  %-19s  %5d  %-7s  %s" % (f._name,
                                                   f._date_last_updated,
                                                   f._file_count,
                                                   f._creator.split('/')[-1],
                                                   f._is_public and "public" or "private")

    def do_EOF(self,line):
        return True

def encode_multipart_formdata(fields,files,mimetype=None):
    """
    Derived from - http://code.activestate.com/recipes/146306/

    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files

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
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
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
    import optparse,getpass
    parser = optparse.OptionParser(usage="Usage: %prog [options]")
    parser.add_option("--username",help="Minus.com username (required)")
    parser.add_option("--password",help="Minus.com password")
    parser.add_option("--scope",default="read_public read_all upload_new modify_all modify_user",
                                help="Application scope")
    parser.add_option("--debug",action="store_true",help="Debug")
    options,args = parser.parse_args()
    if options.username is None:
        parser.print_help()
        sys.exit()
    if options.password is None:
        options.password = getpass.getpass("Minus.com Password: ")
    minus = MinusAPI(options.debug)
    minus.authenticate(options.username,options.password,options.scope)
    user = minus.activeuser()
    cli = MinusCLI()
    cli.connect(user)
    cli.cmdloop()

