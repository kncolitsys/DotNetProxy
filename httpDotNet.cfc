<cfcomponent accessors="true" persistent="true">

<!---
TODO: Make the request via a proxy.
--->

    <cfproperty name="url" required="true" type="string" validate="url" hint="Set the URL, note that it must be a valid URL otherwise it will throw an 'invlaid URL' error.">
    <cfproperty name="port" type="numeric" default="80">
    <cfproperty name="charset" type="string" default="utf-8">
    <cfproperty name="method" type="string" default="GET" validate="regex" validateparams="{pattern=(GET|POST)}" hint="The HTTP request method, must either be GET or POST.">
    <cfproperty name="username" type="string" hint="If the URL is behind NTLM you can pass a username to authenticate. If you do not pass through a username and password it will run as Windows Service user.">
    <cfproperty name="password" type="string" hint="If the URL is behind NTLM you can pass the user's password to authenticate. If you do not pass through a username and password it will run as Windows Service user.">
    <cfproperty name="domain" type="string" hint="If the URL is behind NTLM you can pass the domain.">
    <cfproperty name="IsNTLM" type="boolean" default="false">
    <cfproperty name="proxyserver" type="string">
    <cfproperty name="proxyusername" type="string">
    <cfproperty name="proxypassword" type="string">
    <cfset getAsBinary(false)>

    <!--- Set up a blank struct that replicates the struct returned by a normal CFHTTP --->
    <cfset this.HTTPResponse = {"Charset"="", "ErrorDetail"="", "Mimetype"="", "Statuscode"="", "Filecontent"="", "Responseheader"="", "Text"="NO", "Header"=""}>

    <!--- Set a container for HTTP Request parameters, the default 'User-Agent' is set as ColdFusion-httpDotNet, this can be overwritten. --->
    <cfset this.HTTPRequestParams = {"header"=[{"name"="User-Agent","value"="ColdFusion-httpDotNet"}],"body"=[],"formfield"=[],"xml"=[],"file"=[],"url"=[],"cookie"=[]}>

    <cffunction name="send" access="public" returntype="Struct" description="Make an HTTP request using .Net.">
        <cfargument name="attributes" type="struct" required="false" hint="Attribute-Value pairs.">

        <!--- First we check to make sure we have enough information to make the request ... at the very least a URL. --->
        <cfif (len(trim(getURL())) eq 0 AND (isNull(arguments.attributes)))
                OR (not isNull(arguments.attributes) AND not StructKeyExists(arguments.attributes, "url"))>
            <cfthrow message="At the very least you need to set a URL.">
        <cfelse>
            <!--- If the developer has chosen to pass through a struct of attribute value pairs then we need to call the 'setters' for the properties ---> 
            <cfif not isNull(arguments.attributes)>
                <cfset setAttributes(arguments.attributes)>
            </cfif>
            
            <!--- one final check to make sure at least the url has been set --->
            <cfif len(trim(getURL())) eq 0>
                <cfthrow message="At the very least you need to set a URL.">
            </cfif>
        </cfif>

        <!--- Find out if the request needs to be made as the Windows Service User --->
        <cfset setRunAsService((getIsNTLM() AND trim(len(getUserName())) eq 0 AND trim(len(getPassword())) eq 0 AND trim(len(getDomain())) eq 0))>

        <cftry>
            <!--- Set up the .Net WebClient object --->
            <cfset var objWebClient = CreateObject("dotnet","System.Net.WebClient")>
            
            <cfset objWebClient = useProxy()?setProxy( objWebClient ):objWebClient>
            <cfset objWebClient = getIsNTLM()?setCredentials( objWebClient ):objWebClient>
            
            <cfif getMethod() is 'get'>
               <cfset objWebClient = hasRequestHeaders()?setRequestHeaders( objWebClient ):objWebClient>
               <cfset objWebClient = hasRequestURL()?setRequestURL( objWebClient ):objWebClient>
               <cfset var ResponseBody = objWebClient.DownloadData( getURL() )>
            <cfelse>
                <cfset var PostData = getRequestBodyContent()>
                <cfset objWebClient = hasRequestHeaders()?setRequestHeaders( objWebClient ):objWebClient>
                <cfset var ResponseBody = objWebClient.UploadData( getURL(), "POST", PostData )>
            </cfif>
            
            <cfset var ResponseHeaders = objWebClient.Get_ResponseHeaders()>

            <cfset objWebClient.Dispose()>

            <!--- Now process the .Net Response --->
            <cfset processResponse( ResponseBody, ResponseHeaders )>

            <cfcatch type="any">
                <!--- If the error thrown is an 'object' exception then we need to handle it slightly differently. --->
                <cfset MetaData = getMetaData( cfcatch )>
                   <cfdump var="#cfcatch#">

                    <cfabort>

                <!--- If the Exception thrown is the .Net system.net.webexception then we still need to process it like a normal WebRequest. --->
                <cfif MetaData.getName() is 'system.net.webexception'>
                    <cfset objResponse = processResponse( cfcatch.Get_Response() )>
                <cfelse>
                    <cfrethrow>
                </cfif>
            </cfcatch>
        </cftry>
        <cfreturn this.HTTPResponse>
    </cffunction>

    <cffunction name="setCredentials" access="private" hint="Taking the .Net WebClient object we determine which Credentials we need to attach to the Request object for the NTLM handshake.">
        <cfargument name="ServerRequest" required="true" hint="This must be the .Net request object.">

        <!--- If the URL is behind NTLM then we need to set the relevant objects. ---> 
        <cfset var objCredentialCache = CreateObject("dotnet","System.Net.CredentialCache").init()>

        <cfif getRunAsService()>
            <!--- If request is to use the Service User then we need to treat it slightly differently. --->
            <cfset var objCredentials = objCredentialCache.Get_DefaultCredentials()>

        <cfelse>
            <!--- If request is to use the credentials that were passed through then we need to create the NetworkCredential object with the request. --->
            <cfset var objCredentials = CreateObject("dotnet","System.Net.NetworkCredential").init(getUserName(),getPassword(),getDomain())>
            <cfset var objURI = CreateObject("dotnet","System.Uri").init(getURL())>
            <cfset objCredentialCache.Add(objURI,"NTLM",objCredentials)>

        </cfif>

        <!--- Set the credentials for the request --->
        <cfset arguments.ServerRequest.Set_Credentials( objCredentials )>
        
        <cfreturn arguments.ServerRequest>
    </cffunction>

    <cffunction name="setProxy" access="private" hint="Taking the .Net Request object we set the proxy and the proxyusername/proxypassword.">
        <cfargument name="ServerRequest" required="true" hint="This must be the .Net request object.">
<!--- TODO: This proxy is not working --->
        <cfset var objProxyURI = CreateObject("dotnet","System.Uri").init(getProxyServer())>
        <!--- If the URL is behind NTLM then we need to set the relevant objects. ---> 
        <cfset var objRequestProxy = CreateObject("dotnet","System.Net.WebProxy")>
        <cfset var tempProxy = arguments.ServerRequest.Get_Proxy()>
        <cfset objRequestProxy.Set_Address(objProxyURI)>

        <cfif len(trim(getProxyUsername())) gt 0 AND len(trim(getProxyPassword())) gt 0>
            <cfset var objCredentials = CreateObject("dotnet","System.Net.ICredentials").init(getProxyUserName(),getProxyPassword())>
            <cfset objRequestProxy.Set_Credentials( objCredentials )>
        </cfif>

        <cfset arguments.ServerRequest.Set_Proxy( objRequestProxy )>

        <cfreturn arguments.ServerRequest>
    </cffunction>

    <cffunction name="getRequestBodyContent" access="private" hint="Taking the .Net Request object stream attach both body (formfield) and file (file) content to the Request.">
        <cfset var howManyBodies = ArrayLen(this.HTTPRequestParams["body"])>
        <cfset var howManyFiles = ArrayLen(this.HTTPRequestParams["file"])>
        <cfset var howManyFormFields = ArrayLen(this.HTTPRequestParams["formfield"])>
        <cfset var bodyElem = 0>
        <cfset var body = "">
        <cfset var formElem = 0>
        <cfset var fileElem = 0>
        <cfset var lineBreak = Chr(13) & Chr(10)>
        <cfset var PostDataStream = CreateObject("dotnet","System.IO.MemoryStream")>
        <cfset var boundary = "-----------------------------#dateDiff("s", createDate(1970, 1, 1), now())#">
        <cfset var ContentType = "multipart/form-data; boundary=#boundary#">
        <cfset var objText = CreateObject("dotnet","System.Text.UTF8Encoding")>

<!--- TODO: neaten this up. Setting the content type while it works okay is not entirely correct. --->

        <!--- If an XML parameter i.e. addParam(type="xml") is being passed through then no other body types can be passed through. --->
        <cfif hasRequestXML()>
            <cfset var xmlDoc = this.HTTPRequestParams["xml"][1]>
            <cfset FormDataBytes = objText.GetBytes(xmlDoc)>
            <cfset PostDataStream.Write(FormDataBytes, 0, ArrayLen(FormDataBytes))>
            <cfset PostDataArray = PostDataStream.ToArray()>
            <cfset PostDataStream.Close()>

            <cfreturn PostDataArray>
        </cfif>

        <cfloop from="1" to="#howManyFormFields#" index="formElem">

            <cfset s = '--' & boundary & lineBreak>
            <cfset s = s & 'Content-Disposition: form-data; name="#this.HTTPRequestParams["formfield"][formElem]["name"]#";' & lineBreak>
            <cfset s = s & lineBreak>
            <cfset s = s & this.HTTPRequestParams["formfield"][formElem]["value"] & lineBreak>
            
            <cfset FormDataBytes = objText.GetBytes(s)>
            <cfset PostDataStream.Write(FormDataBytes, 0, ArrayLen(FormDataBytes))>

        </cfloop>
        
        <cfif hasRequestFile()>

            <!--- Now Process the Files so they can be posted --->
            <cfloop from="1" to="#howManyFiles#" index="fileElem">
                
                <cfset var MimeType = getMimeType(this.HTTPRequestParams["file"][fileElem]["file"])>
                <cfset FileBytes = CreateObject("dotnet","System.IO.File").ReadAllBytes(this.HTTPRequestParams["file"][fileElem]["file"])>

                <cfset s = '--' & boundary & lineBreak>
                <cfset s = s & 'Content-Disposition: form-data; name="#this.HTTPRequestParams["file"][fileElem]["name"]#"; filename="#this.HTTPRequestParams["file"][fileElem]["file"]#"' & lineBreak>
                <cfset s = s & 'Content-Type: #MimeType#' & lineBreak>
                <cfset s = s & 'Content-Transfer-Encoding: binary' & lineBreak>
                <cfset s = s & lineBreak>
                
                <cfset FormDataBytes = objText.GetBytes(s)>
                <cfset PostDataStream.Write(FormDataBytes, 0, ArrayLen(FormDataBytes))>
                <cfset PostDataStream.Write(FileBytes, 0, ArrayLen(FileBytes))>

                <cfset s = lineBreak>

                <cfset FormDataBytes = objText.GetBytes(s)>
                <cfset PostDataStream.Write(FormDataBytes, 0, ArrayLen(FormDataBytes))>

            </cfloop>
        </cfif>
        
        <cfset s = '--' & boundary & '--' & lineBreak>
        <cfset s = s & lineBreak>

        <cfset FormDataBytes = objText.GetBytes(s)>

        <cfset PostDataStream.Write(FormDataBytes, 0, ArrayLen(FormDataBytes))>
        <cfset PostDataArray = PostDataStream.ToArray()>
        <cfset PostDataStream.Close()>

        <cfset addParam(type="header", name="Content-Type", value=ContentType)>

        <cfreturn PostDataArray>
    </cffunction>

    <cffunction name="setRequestHeaders" access="private" hint="Taking the .Net Request object we set any headers the developer wants to attache to the request.">
        <cfargument name="WebClient" required="true" hint="This must be the .Net web client object.">

        <cfset var howManyHeaders = ArrayLen(this.HTTPRequestParams["header"])>
        <cfset var howManyCookies = ArrayLen(this.HTTPRequestParams["cookie"])>
        <cfset var header = 0>
        <cfset var cookie = 0>
        <cfset var cookies = "">
        
        <cfif howManyCookies gt 0>
            <cfloop from="1" to="#howManyCookies#" index="cookie">
                <cfset cookies = cookies & "#this.HTTPRequestParams["cookie"][cookie]["name"]#=#this.HTTPRequestParams["cookie"][cookie]["value"]#" & ((cookie lt howManyCookies)?";":"")>
            </cfloop>
            
            <!--- Those headers that are passed in that are not .Net protected can be set using the Add function --->
            <cfset arguments.WebClient.Get_Headers().Add("cookie", cookies)>
            
        </cfif>

        <cfloop from="1" to="#howManyHeaders#" index="header">

            <!--- Some headers cannot be set using the 'Add' function as they are protected .Net  and also it is not possible to run these methods dynamically which is unfortunate. --->
            <cfswitch expression="#lcase(this.HTTPRequestParams['header'][header]['name'])#">
                <cfcase value="Accept">
                    <cfset arguments.WebClient.Set_Accept(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Connection">
                    <cfset arguments.WebClient.Set_Connection(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Expect">
                    <cfset arguments.WebClient.Set_Expect(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Date">
                    <cfset arguments.WebClient.Set_Date(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Host">
                    <cfset arguments.WebClient.Set_Host(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="If-Modified-Since">
                    <cfset arguments.WebClient.Set_IfModifiedSince(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Range">
                    <cfset arguments.WebClient.Set_Range(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfcase value="Referer">
                    <cfset arguments.WebClient.Set_Referer(this.HTTPRequestParams['header'][header]['value'])>
                </cfcase>
                <cfdefaultcase>
                    <!--- Those headers that are passed in that are not .Net protected can be set using the Add function --->
                    <cfset arguments.WebClient.Get_Headers().Add(this.HTTPRequestParams['header'][header]['name'], this.HTTPRequestParams['header'][header]['value'])>
                </cfdefaultcase>
            </cfswitch>
        </cfloop>

        <cfreturn arguments.WebClient>
    </cffunction>
    
    <cffunction name="setRequestURL" access="private" hint="Taking the .Net Request object we set any URL parameters the developer wants to attach to the request.">
        <cfargument name="WebClient" required="true" hint="This must be the .Net web client object.">

        <cfset var howManyURLParams = ArrayLen(this.HTTPRequestParams["url"])>
        <cfset var urlParam = 0>
        <cfset var objNameValue = CreateObject("dotnet","System.Collections.Specialized.NameValueCollection")> 

        <cfloop from="1" to="#howManyURLParams#" index="urlParam">
            <cfset objNameValue.Add(this.HTTPRequestParams["url"][urlParam].name, this.HTTPRequestParams["url"][urlParam].value)>
        </cfloop>
        
        <!--- Now attach the name value pair to the WebClient object. --->
        <cfset arguments.WebClient.Set_QueryString( objNameValue )>

        <cfreturn arguments.WebClient>
    </cffunction>

    <cffunction name="processResponse" access="private" hint="Taking the .Net Response object this function processes it and sets up a regular CFHTTP struct.">
        <cfargument name="Body" required="true" hint="This must be the WebClient byte array.">
        <cfargument name="Headers" required="true" hint="This must be the WebClient byte array.">
        
        <cfif IsGetAsBinary()>
            <cfset var Convert = CreateObject("dotnet","System.Convert")>
            <cfset BodyBase64 = Convert.ToBase64String(arguments.Body)>
            <cfset ResponseBodyString = BinaryDecode(BodyBase64, "base64")>
        <cfelse>
            <cfset var objText = CreateObject("dotnet","System.Text.UTF8Encoding")>
            <cfset var ResponseBodyString = objText.GetString(arguments.Body)>
        </cfif>
        
        <!--- Process the Response Headers --->
        <cfset var arrHeaders = arguments.Headers.Get_AllKeys()>
        <cfset var howManyHeaders = ArrayLen(arrHeaders)>
        <cfset var ResponseHeaders = {}>
        <cfset var i = 0>
        <cfset var HeaderValue = "">
        <cfset var howManyHeaderValues = 0>
        <cfset var headerPairs = 0>
        <cfset var HeaderName = "">
        <cfset var SetCookies = "">
        <cfset var arrCookies = []>
        <cfset var howManyCookies = 0>
        <cfset var biscuit = 0>
        
        <cfloop from="1" to="#howManyHeaders#" index="header">
            
            <cfset howManyHeaderValues = ArrayLen(arguments.Headers.GetValues(arrHeaders[header]))>
            <cfset HeaderName = arrHeaders[header]>
            
            <!--- The 'set-cookie' header values are delimited by commas ',', a comma sometimes appears in the 'Expires' value of a cookie. --->
            <cfif HeaderName is 'set-cookie'>
                <cfset SetCookies = arguments.Headers.Get(HeaderName)>
                <cfset SetCookies = REReplace(SetCookies,"(,(?=[^ ]))","|","all")>
                <cfset arrCookies = ListToArray(SetCookies,"|")>
                <cfset howManyCookies = ArrayLen(arrCookies)>
                <cfset HeaderValue = {}>
                <cfloop from="1" to="#howManyCookies#" index="biscuit">
                    <cfset HeaderValue[biscuit] = arrCookies[biscuit]>
                </cfloop>
            <cfelse>
                <cfset HeaderValue = arguments.Headers.GetValues(HeaderName)[1]>
            </cfif>

            <cfset ResponseHeaders[HeaderName] = HeaderValue>
        </cfloop>
        <cfset ResponseHeaders["Status_Code"] = 200>
        <cfset ResponseHeaders["Explanation"] = "OK">

        <cfset this.HTTPResponse["ResponseHeader"] = ResponseHeaders>
        <!--- Set the values of the Response Struct --->
        <cfset this.HTTPResponse["FileContent"] = ResponseBodyString>
        <cfset this.HTTPResponse["Charset"] = (StructKeyExists(ResponseHeaders, "Content-Type") AND ListLen(ResponseHeaders["Content-Type"], ";") eq 2)?(ListLen(ListLast(ResponseHeaders["Content-Type"],";"),"=") eq 2?ListLast(ListLast(ResponseHeaders["Content-Type"],";"),"="):""):"">
        <cfset this.HTTPResponse["Statuscode"] = "200 OK">
        <cfset this.HTTPResponse["Mimetype"] = (StructKeyExists(ResponseHeaders, "Content-Type") AND ListLen(ResponseHeaders["Content-Type"], ";") eq 2)?ListFirst(ResponseHeaders["Content-Type"],";"):"">
        <cfset this.HTTPResponse["Header"] = arguments.Headers.toString()>

        <cfif not StructKeyExists(ResponseHeaders, "content-type") 
                OR (StructKeyExists(ResponseHeaders, "content-type") 
                    AND (ResponseHeaders["content-type"] contains 'text' 
                         OR ResponseHeaders["content-type"] contains 'message' 
                         OR ResponseHeaders["content-type"] contains 'application/octet-stream'))>
            <cfset this.HTTPResponse["Text"] = "YES">
        </cfif>

    </cffunction>
    
    <cffunction name="addParam" access="public" output="false" returntype="void" hint="This function takes the HTTP parameters you would like to send with your request.">
        <cfargument name="type" required="true">
        <cfargument name="encoded" default="true">
        <cfargument name="file">
        <cfargument name="mimeType">
        <cfargument name="name">
        <cfargument name="value">

        <cfset var typeOptions = "header,cgi,body,xml,file,url,formfield,cookie">
        <cfset var tempStr = {}>
        <!--- Essentially the header and cgi are the same thing only cgi has the encoded option. --->
        <cfset var ParamType = lcase((arguments.type is 'cgi')?"header":arguments.type)>

        <cfswitch expression="#ParamType#">
            <cfcase value="header,formfield,cookie,url">
                <cfif StructKeyExists(arguments, "name") AND len(trim(arguments.name)) gt 0 AND StructKeyExists(arguments, "value")>
                    <cfset tempStr = {}>
                    <cfset tempStr["name"] = arguments.name>
                    <cfif (ListContains("cgi,formfield",lcase(arguments.type)) AND arguments.encoded) OR lcase(arguments.type is 'url')>
                        <cfset tempStr["value"] = URLEncodedFormat(arguments.value)>
                    <cfelse>
                        <cfset tempStr["value"] = arguments.value>
                    </cfif>
                    <cfif arguments.type is 'formfield' AND getMethod() is "post">
                        <cfset addParam(type="body",value="#arguments.name#=#arguments.value#")>
                    </cfif>
                <cfelse>
                    <cfthrow message="When setting a 'header', 'formfield', 'cgi' or 'cookie' parameter you must set the 'name' AND 'value' arguments.">
                </cfif>
            </cfcase>
            <cfcase value="body">
                <cfif StructKeyExists(arguments, "value")>
                    <cfset tempStr = arguments.value>
                <cfelse>
                    <cfthrow message="When setting the 'body' parameter you must pass through the 'value' attribute.">
                </cfif>
            </cfcase>
            <cfcase value="xml">
                <cfif StructKeyExists(arguments, "value")>
                    <cfset tempStr = arguments.value>
                    <cfset addParam(type="header",name="content-type",value="text/xml; charset=UTF-8")>
                <cfelse>
                    <cfthrow message="When setting the 'xml' parameter you must pass through the 'value' attribute.">
                </cfif>
            </cfcase>
            <cfcase value="file">
                <cfif StructKeyExists(arguments, "name") AND len(trim(arguments.name)) gt 0 AND StructKeyExists(arguments, "file") AND len(trim(arguments.file)) AND FileExists(arguments.file)>
                    <cfset tempStr = {}>
                    <cfset tempStr["name"] = arguments.name>
                    <cfset tempStr["file"] = arguments.file>
                <cfelse>
                    <cfthrow message="When posting a 'file' parameter you must set the 'name' AND 'file' and the 'file' path must be valid arguments.">
                </cfif>
            </cfcase>
            <cfdefaultcase>
                <cfthrow message="The 'type' passed in is not valid">
            </cfdefaultcase>
        </cfswitch>

        <cfif not StructKeyExists(this.HTTPRequestParams , ParamType)>
            <cfset this.HTTPRequestParams["#ParamType#"] = []>
        </cfif>

        <cfset ArrayAppend(this.HTTPRequestParams["#ParamType#"],tempStr)>

    </cffunction>

    <cffunction name="setAttributes" access="public" output="false" returntype="void" hint="This helper function takes the struct of values and then attempts to call the setters dynamically.">
        <cfargument name="attributes">
        <!--- Looping over the struct we determine if the setter exists in 'this' and if it does we set the value with the value of the struct. --->
        <cfloop collection="#arguments.attributes#" item="key" >
            <cfif StructKeyExists(this, "set#key#")>
                <cfset tempSetFunc = this["set#key#"]>
                <cfif isCustomFunction(tempSetFunc)>
                    <cfset tempSetFunc(arguments.attributes[key])>
                </cfif>
            </cfif>
        </cfloop>
    </cffunction>
    
    <cffunction name="getAsBinary" access="public" output="false" returntype="void" hint="Set the boolean value whether or to return the filecontent as binary.">
        <cfargument name="AsBinary" type="boolean">
        <cfset this.IsAsBinary = arguments.AsBinary>
    </cffunction>
    <cffunction name="IsGetAsBinary" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not to return the filecontent as binary.">
        <cfreturn this.IsAsBinary>
    </cffunction>
    
    <cffunction name="setRunAsService" access="private" output="false" returntype="void" hint="Set the boolean value whether or not this should run as the service's user account.">
        <cfargument name="runAsService" type="boolean">
        <cfset this.runAsService = arguments.runAsService>
    </cffunction>
    <cffunction name="getRunAsService" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not this should run as the service's user account.">
        <cfreturn this.runAsService>
    </cffunction>

    <cffunction name="hasRequestHeaders" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not any Header parameters need to be set for the request.">
        <cfset var b = hasRequestParam("header")>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestURL" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not url parameters are being passed through (query string).">
        <cfset var b = hasRequestParam("url")>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestBodyContent" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not any there are either Body OR File parameters need to be set for the request.">
        <cfset var b = (hasRequestBody() OR hasRequestFile() OR hasRequestXML())>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestBody" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not any body parameters need to be set for the request.">
        <cfset var b = hasRequestParam("body")>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestFile" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not any file parameters need to be set for the request.">
        <cfset var b = hasRequestParam("file")>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestXML" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or xml data is being posted.">
        <cfset var b = hasRequestParam("xml")>
        <cfreturn b>
    </cffunction>

    <cffunction name="hasRequestParam" access="private" output="false" returntype="boolean" hint="Get the boolean value whether or not any Header parameters need to be set for the request.">
        <cfargument name="type" required="true">
        <cfset var hasRequestParam = (StructKeyExists(this.HTTPRequestParams, arguments.type) AND IsArray(this.HTTPRequestParams["#arguments.type#"]) AND ArrayLen(this.HTTPRequestParams["#arguments.type#"]) gt 0)>
        <cfreturn hasRequestParam>
    </cffunction>
    
    <cffunction name="useProxy" access="private" output="false" returntype="boolean" hint="Find out if the proxy server has been set.">
        <cfset var b = (Len(trim(getProxyServer())) gt 0)?true:false>
        <cfreturn b>
    </cffunction>

    <cffunction name="getMimeType" access="private" output="false" returntype="any" hint="This determines the uploaded file's mimetype. If the mimetype is not 'registered' it will default to 'application/octet-stream'.">
        <cfargument name="file" required="true">
        <cfset var objFile = createObject("java", "java.io.File").init(arguments.file)>
        <cfset var MimeTypeMap = createObject("java", "javax.activation.MimetypesFileTypeMap")>
        <cfset var FileMimeType = MimeTypeMap.getContentType(objFile)>
        
        <cfif len(trim(FileMimeType)) eq 0>
            <cfset FileMimeType = "application/octet-stream"> 
        </cfif>
        
        <cfreturn FileMimeType>
    </cffunction>
    
    <cffunction name="isTestedCLRVersion" access="public" output="false" returntype="boolean" hint="Finds out if this runs on the users current .Net version.">
        <cfset var objVersion = CreateObject("dotnet","System.Environment")>
        <cfset var RunningVersion = objVersion.Get_Version().ToString()> 
        <cfset var arrTestedVersions = ["4.0.30319.235","2.0.50727.5448"]>
        <cfset var HowManyVersions = ArrayLen(arrTestedVersions)>
        <cfset var canRun = false>
        <cfset var version = 0>

        <cfloop from="1" to="#HowManyVersions#" index="version">
            <cfif arrTestedVersions[version] eq RunningVersion>
                <cfset canRun = true>
                <cfbreak />
            </cfif>
        </cfloop>
          
        <cfreturn canRun>
    </cffunction>

    <cffunction name="getCLRVersion" access="public" output="false" returntype="string" hint="Find out the version of common language runtime (CLR).">
        <cfset var objVersion = CreateObject("dotnet","System.Environment")>
        <cfset var RunningVersion = objVersion.Get_Version().ToString()> 
        <cfreturn RunningVersion>
    </cffunction>

</cfcomponent>