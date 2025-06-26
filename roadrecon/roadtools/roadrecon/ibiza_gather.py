import argparse
import asyncio
import json
import os
import sys
import time
import traceback
import warnings

import aiohttp
import requests
import roadtools.roadlib.metadef.database_ibiza as database_ibiza
#from roadlib.metadef.database import Domain
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.metadef.database_ibiza import (
    Application, ApplicationRef, AdministrativeUnit, AppRoleAssignment,
    AuthorizationPolicy, Contact, Device, DirectoryRole, DirectorySetting,
    EligibleRoleAssignment, ExtensionProperty, Group, OAuth2PermissionGrant,
    Policy, RoleAssignment, RoleDefinition, ServicePrincipal, TenantDetail, TenantProperties,
    User,AppRoleAssignmentto, lnk_au_member_device, lnk_au_member_group, lnk_au_member_user,
    lnk_device_owner, lnk_group_member_contact, lnk_group_member_device,
    lnk_group_member_group, lnk_group_member_serviceprincipal,
    lnk_group_member_user, lnk_group_owner_serviceprincipal,
    lnk_group_owner_user)
from sqlalchemy import bindparam, func, text
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from roadtools.roadlib.deviceauth import DeviceAuthentication

warnings.simplefilter('ignore')
token = None
expiretime = None
headers = {}
dburl = ''
urlcounter = 0
groupcounter = 0
totalgroups = 0
devicecounter = 0
totaldevices = 0

tokencounter = 0
tokenfilltime = time.time()

clientRequestId = "01ea3335-b7a6-4552-8bd8-562ee32fd818"

msgraphToken = None

MAX_GROUPS = 3000
MAX_REQ_PER_SEC = 600.0

def mknext(url, prevurl):
    if url is None:
        return None
    if url.startswith('https://'):
        # Absolute URL
        return url
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url
    return '/'.join(parts[:-1]) + '/' + url

async def dumphelper(url, method=requests.get, json_body=None):
    global urlcounter, tokencounter
    nexturl = url


    while nexturl:
        checktoken()
        await ratelimit()
        try:
            urlcounter += 1
            
            headers['X-Ms-Client-Request-Id']=clientRequestId
            request_kwargs = {'headers': headers}
            if json_body is not None:
                request_kwargs['json'] = json_body

            async with method(nexturl, **request_kwargs, **proxy_config, verify_ssl=disable_verify_switch) as req:
                # Rate limit handling
                if req.status == 429:
                    if tokencounter > 0:
                        tokencounter -= 10 * MAX_REQ_PER_SEC
                        print('Sleeping because of rate-limit hit')
                    continue

                if req.status != 200:
                    if req.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                        return
                    print(f'Error {req.status} for URL {nexturl}')
                    print('')
                    return

                try:
                    objects = await req.json()
                except json.decoder.JSONDecodeError:
                    print(req.content)
                    print('')
                    return

                # Handle pagination (if nextLink exists)
                # Update json body for pagination instead of changing the URL for certain POST requests
                if json_body is not None:
                    next_link_value = objects.get('nextLink')
                    if next_link_value is not None:
                        json_body['nextLink'] = next_link_value
                        nexturl = url # URL will be the same - just the  nextLink body property needs to be updated
                    else:
                        nexturl = None
                else:
                    # Only use nexturl if not doing in-body pagination
                    nexturl = mknext(objects.get('nextLink'), url)
                
                # print(objects)
                # Check if 'items' key exists in the objects dictionary
                if 'items' in objects:
                    # Iterate over each item in the 'items' list
                    for robject in objects['items']:
                        yield robject
                elif 'appList' in objects:
                    for robject in objects['appList']:
                        yield robject
                elif 'value' in objects:
                    for robject in objects['value']:
                        yield robject
                else:
                    # If 'items' key does not exist, yield the entire object
                    yield objects

        except Exception as exc:
            print(exc)
            return
        

async def ratelimit():
    global tokencounter, tokenfilltime
    if tokencounter < MAX_REQ_PER_SEC:
        now = time.time()
        to_add = MAX_REQ_PER_SEC * (now - tokenfilltime)
        tokencounter = min(MAX_REQ_PER_SEC, tokencounter + to_add)
        tokenfilltime = now
    if tokencounter < 1:
        # print('Ratelimit reached')
        await asyncio.sleep(0.1)
        await ratelimit()
    else:
        tokencounter -= 1


def checktoken():
    global token, expiretime
    if time.time() > expiretime - 300:
        auth = Authentication()
        try:
            auth.client_id = token['_clientId']
        except KeyError:
            auth.client_id = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'# Azure Portal
        try:
            auth.resource_uri = tokendata['aud']
        except KeyError:
            auth.resource_uri = '74658136-14ec-4630-ad9b-26e160ff0fc6'# ibiza IAM API
        auth.tenant = token['tenantId']
        auth.tokendata = token
        if 'useragent' in token:
            auth.set_user_agent(token['useragent'])
        if 'originheader' in token:
            auth.set_origin_value(token['originheader'])
        if 'refreshToken' in token:
            print("- Attempting token refresh -")
            token = auth.authenticate_with_refresh(token)
            headers['Authorization'] = '%s %s' % (token['tokenType'], token['accessToken'])
            expiretime = int(time.time()) + int(token['expiresIn'])
            print('+ Refreshed token +')
            return True
        elif time.time() > expiretime:
            print('Access token is expired, but no access to refresh token! Dumping will fail')
            return False
    return True

async def dumpsingle(url, method):

    global urlcounter, tokencounter, proxy_config, disable_verify_switch
    checktoken()
    await ratelimit()
    headers['X-Ms-Client-Request-Id']=clientRequestId
    try:
        urlcounter += 1
        async with method(url, headers=headers, **proxy_config, verify_ssl=disable_verify_switch) as res:
            if res.status == 429:
                if tokencounter > 0:
                    tokencounter -= 10*MAX_REQ_PER_SEC
                    print('Sleeping because of rate-limit hit')
                obj = await dumpsingle(url, method)
                return obj
            if res.status != 200:
                # This can happen
                if res.status == 404 and 'applicationRefs' in url:
                    return
                # Ignore default users role not being found
                if res.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                    return
                print('Error %d for URL %s' % (res.status, url))
                return
            objects = await res.json()
            return objects
    except Exception as exc:
        print(exc)
        return
    


def enginecommit(engine, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['objectId']
        )
    elif 'sqlite' in dburl and ignore:
        statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
    else:
        statement = dbtype.__table__.insert()
    with engine.begin() as conn:
        conn.execute(
            statement,
            cache
        )

def commit(session, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['objectId']
        )
    elif 'sqlite' in dburl and ignore:
        statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
    else:
        statement = dbtype.__table__.insert()
    session.execute(
        statement,
        cache
    )

def commitlink(session, cachedict, ignore=False):
    global dburl
    for linktable, cache in cachedict.items():
        if 'postgresql' in dburl and ignore:
            insertst = pginsert(linktable)
            statement = insertst.on_conflict_do_nothing(
                index_elements=['objectId']
            )
        elif 'sqlite' in dburl and ignore:
            statement = linktable.insert().prefix_with('OR IGNORE')
        else:
            statement = linktable.insert()
        # print(cache)
        session.execute(
            statement,
            cache
        )

def commitmfa(session, dbtype, cache):
    try:
        statement = dbtype.__table__.update().where(dbtype.objectId == bindparam('userid'))
    except:
        statement = dbtype.__table__.update().where(dbtype.id == bindparam('userid'))
    session.execute(
        statement,
        cache
    )

async def queue_processor(queue):
    while True:
        task = await queue.get()
        # task is already a coroutine, so we wait for it to finish
        await task
        queue.task_done()

class DataDumper(object):
    def __init__(self, tenantid, ahsession=None, engine=None, session=None):
 
        self.tenantid = tenantid
        self.session = session
        self.engine = engine
        self.ahsession = ahsession

    async def dump_object(self, objecttype, dbtype, method=None, json_body=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://main.iam.ad.ext.azure.com/api/%s' % (objecttype)

        cache = []
        async for obj in dumphelper(url, method=method, json_body=json_body):
            cache.append(obj)
            # print(json.dumps(cache, indent=2))
            if len(cache) > 1000:
                enginecommit(self.engine, dbtype, cache)
                del cache[:]
        # print("[+] Cache:", cache)
        if len(cache) > 0:
            enginecommit(self.engine, dbtype, cache)
        

    async def dump_object_msgraph(self, objecttype, dbtype, method=None):
        global token, msgraphToken
        # Dont want to refresh the token every time we call this function
        if msgraphToken is None:
            print("[INFO] Refreshing token to graph.microsoft.com")
            auth = Authentication()
            # tokendata = auth.parse_accesstoken(token['accessToken'])
            # refreshToken = token['refreshToken']
            if tokendata['aud'] not in ('https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000'):
                auth.client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Azure CLI
                auth.resource_uri = "https://graph.microsoft.com"
            print(f"[INFO] Using Client: {auth.client_id} - This might get blocked by Conditional Access") # TO DO: still to make this process better
            auth.tenant = token['tenantId']
            auth.tokendata = token
            if 'useragent' in token:
                auth.set_user_agent(token['useragent'])
            if 'originheader' in token:
                auth.set_origin_value(token['originheader'])
            if 'refreshToken' in token:
                print("- Attempting token refresh -")
                msgraphToken = auth.authenticate_with_refresh(token)
                headers['Authorization'] = '%s %s' % (msgraphToken['tokenType'], msgraphToken['accessToken'])
                expiretime = int(time.time()) + int(msgraphToken['expiresIn'])
                print('+ Refreshed token +')
            elif time.time() > expiretime:
                print('Access token is expired, but no access to refresh token! Dumping will fail')
                return False

        if method is None:
            method = self.ahsession.get
        url = 'https://graph.microsoft.com/v1.0/%s' % (objecttype)
        
        cache = []
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            # print(json.dumps(cache, indent=2))
            if len(cache) > 1000:
                enginecommit(self.engine, dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            enginecommit(self.engine, dbtype, cache)

    async def dump_org_details(self, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://main.iam.ad.ext.azure.com/api/Directories/%s/Details' % (self.tenantid)
        
        cache = []
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            # print(json.dumps(cache, indent=2))
            if len(cache) > 1000:
                enginecommit(self.engine, dbtype, cache)
                del cache[:]
        if len(cache) > 0:
                enginecommit(self.engine, dbtype, cache)
    
    async def dump_conditional_access_policies(self, dbtype, method=None):
        """
        Enumerates all Conditional Access Policies and fetches their full detail individually.
        """

        if method is None:
            method = self.ahsession.get
        url = 'https://main.iam.ad.ext.azure.com/api/Policies/Policies?top=999&nextLink=' 
        cache = []
        async for obj in dumphelper(url, method=method):
            policy_id = obj.get("policyId")
            print(policy_id)
            if policy_id:
                detail_url = 'https://main.iam.ad.ext.azure.com/api/Policies/%s' % (policy_id)
                policy_details = await dumpsingle(detail_url, method=method) # TO DO - Make faster
                cache.append(policy_details)
                if len(cache) > 1000:
                    enginecommit(self.engine, dbtype, cache)
                    del cache[:]
        if len(cache) > 0:
                enginecommit(self.engine, dbtype, cache)
    
    async def dump_sps_to_db(self, url, method, cache):
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        cache.append(obj)

    async def dump_service_principal_object(self, objecttype, dbtype, post_body):
        """
        Dump paginated objects via a POST request and store them in the database.
        """
        url = 'https://main.iam.ad.ext.azure.com/api/%s' % (objecttype)
        method = self.ahsession.post
        cache = []
        jobs = []
        i = 0
            
        async for obj in dumphelper(url, method=method, json_body=post_body):
            
            application_id = obj.get("objectId")
            if application_id:
                detail_url = 'https://main.iam.ad.ext.azure.com/api/ManagedApplications/%s' % (application_id)
                jobs.append(self.dump_sps_to_db(detail_url, method=self.ahsession.get, cache=cache))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                enginecommit(self.engine, dbtype, cache)
                del cache[:]
                i = 0
        if i > 0:
                await asyncio.gather(*jobs)
                enginecommit(self.engine, dbtype, cache)
        del cache[:]

    async def dump_object_cache(self, objecttype, method, json_body=None):
        """
        Dump objects via a POST request and return them for further parseing
        """
        url = 'https://main.iam.ad.ext.azure.com/api/%s' % (objecttype)
        if method is None:
            method = self.ahsession.post
        cache = []
        async for obj in dumphelper(url, method=method, json_body=json_body):
            cache.append(obj)
        return cache
    
    # async def dump_service_principal_object(self, obj, dbtype):
    #     """
    #     Dump paginated objects via a POST request and store them in the database.
    #     """ 
    #     cache = []
       
    #     application_id = obj.get("objectId")
    #     if application_id:
    #         detail_url = 'https://main.iam.ad.ext.azure.com/api/ManagedApplications/%s' % (application_id)
    #         policy_details = await dumpsingle(detail_url, method=self.ahsession.get)
            
    #         if isinstance(policy_details, dict):
    #             cache.append(policy_details)
    #         # else:
    #         #     print(f"Unexpected object type: {type(policy_details)}")
    #         if len(cache) > 1000:
    #             enginecommit(self.engine, dbtype, cache)
    #             del cache[:]
    #     if len(cache) > 0:
    #             enginecommit(self.engine, dbtype, cache)


        # next_link = ''
        # while True:
        #     body = post_body.copy()
        #     body['nextLink'] = next_link

        #     async for obj in dumphelper_post(url, method=method, json_body=body):
        #         cache.append(obj)
        #         if len(cache) > 1000:
        #             commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        #             del cache[:]
            
        #     if not next_link:
        #         break
        #     next_link = obj.get('nextLink')
        #     if not next_link:
        #         break

        # if cache:
        #     commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        # self.session.commit()

    

    async def dump_l_to_db(self, url, method, mapping, linkname, childtbl, parent):
        global groupcounter, totalgroups, devicecounter, totaldevices
        i = 0
        # print("URL FIRST:", url)
        # Essentially this takes a URL sends a request and recieves a response immediately and then tries to parse the response with objectId, objclass = obj['url'].split('/')[-2:] - Previously AAD graph returned an object with a load of URLs which is why this logic is here to get the URLs for the linked objects
        async for obj in dumphelper(url, method=method):
            
            try:
                objectId = obj['objectId']
            except:
                objectId = obj['id']
            
            objclass = obj['@odata.type'].strip('#')
           
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    childtbl, linkname = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s for parent %s' % (objclass, parent.__table__))
                    continue
            child = self.session.get(childtbl, objectId)
            if not child:
                try:
                    parentname = parent.displayName
                except AttributeError:
                    parentname = parent.objectId
                print('Non-existing child found on %s %s: %s' % (parent.__table__, parentname, objectId))
                continue
            getattr(parent, linkname).append(child)
            i += 1
            if i > 1000:
                self.session.commit()
                i = 0
        if str(parent.__table__) == 'Groups':
            groupcounter += 1
            print('Done processing {0}/{1} groups'.format(int(groupcounter/2), totalgroups), end='\r')

    async def dump_l_to_linktable(self, url, method, mapping, parentid, objecttype):
        global groupcounter, totalgroups, devicecounter, totaldevices
        i = 0
        cache = {}
        async for obj in dumphelper(url, method=method):
            objectId, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    linktable, leftcol, rightcol = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s for parent %s' % (objclass, objecttype))
                    continue
            try:
                cache[linktable].append({leftcol: parentid, rightcol: objectId})
            except KeyError:
                cache[linktable] = [{leftcol: parentid, rightcol: objectId}]
            i += 1
            if i > 1000:
                commitlink(self.session, cache)
                cache = {}
                i = 0
        commitlink(self.session, cache)
        if str(objecttype) == 'groups':
            groupcounter += 1
            print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(groupcounter/2), totalgroups, devicecounter, totaldevices), end='\r')
        if str(objecttype) == 'devices':
            devicecounter += 1
            print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(groupcounter/2), totalgroups, devicecounter, totaldevices), end='\r')

    async def dump_links(self, objecttype, linktype, parenttbl, mapping=None, linkname=None, childtbl=None, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl).all()
        jobs = []
        i = 0
        for parent in parents:
            if hasattr(parent, 'objectId'):
                url = 'https://graph.microsoft.com/v1.0/%s/%s/%s' % (objecttype, parent.objectId, linktype)
            elif hasattr(parent, 'id'):
                url = 'https://graph.microsoft.com/v1.0/%s/%s/%s' % (objecttype, parent.id, linktype)

            jobs.append(self.dump_l_to_db(url, method, mapping, linkname, childtbl, parent))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                i = 0
        await asyncio.gather(*jobs)
        self.session.commit()

    async def dump_links_with_queue(self, queue, objecttype, linktype, parenttbl, mapping=None, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        for parentid, in parents:
            url = 'https://graph.microsoft.com/v1.0/%s/%s/%s' % (objecttype, parentid, linktype)
            
            # Chunk it to avoid huge memory usage
            await queue.put(self.dump_l_to_linktable(url, method, mapping, parentid, objecttype))
        await queue.join()
        self.session.commit()

    async def dump_mfa_to_db(self, url, method, parentid, cache):
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        cache.append({'userid':parentid,
                      'isMfaRegistered':obj['isMfaRegistered'],
                      'isMfaCapable':obj['isMfaCapable'],
                      'isSsprRegistered':obj['isSsprRegistered'],
                      'isSsprEnabled':obj['isSsprEnabled'],
                      'isSsprCapable':obj['isSsprCapable'],
                      'isPasswordlessCapable': obj['isPasswordlessCapable'],
                      'methodsRegistered':obj['methodsRegistered'],
                      'systemPreferredAuthenticationMethods':obj['systemPreferredAuthenticationMethods']})
        
    async def dump_mfa(self, parenttbl, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        cache = []
        i = 0
        for parentid, in parents:
            url = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/%s' % (parentid)
            
            jobs.append(self.dump_mfa_to_db(url, method, parentid, cache))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                commitmfa(self.session, parenttbl, cache)
                del cache[:]
                i = 0
        await asyncio.gather(*jobs)
        commitmfa(self.session, parenttbl, cache)
        del cache[:]

    async def dump_lo_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for multiple linked objects (returned as a list)
        """
        async for obj in dumphelper(url, method=method):
            # objectId, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            # print(parent.objectId, obj)
            # print(obj)
            cache.append(obj)
            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                del cache[:]

    async def dump_so_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for objects that are returned as single objects (direct values)
        """
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        cache.append(obj)
        if len(cache) > 1000:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            del cache[:]

    async def dump_linked_objects(self, objecttype, linktype, parenttbl, linkobjecttype, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.microsoft.com/v1.0/%s/%s/%s' % (objecttype, parent.objectId, linktype)
            
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
        self.session.commit()


    async def dump_object_expansion(self, objecttype, dbtype, expandprop, linkname, childtbl, mapping=None, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://graph.microsoft.com/v1.0/%s?$expand=%s' % (objecttype, expandprop)
        
        i = 0
        async for obj in dumphelper(url, method=method):
            if len(obj[expandprop]) > 0:
                try:
                    parent = self.session.get(dbtype, obj['objectId'])
                except:
                    parent = self.session.get(dbtype, obj['id'])
                if not parent:
                    print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, expandprop, obj['objectId']))
                    continue
                for epdata in obj[expandprop]:
                    objclass = epdata['@odata.type'].strip('#')
                    if mapping is not None:
                        try:
                            childtbl, linkname = mapping[objclass]
                        except KeyError:
                            print('Unsupported member type: %s' % objclass)
                            continue
                    try:
                        child = self.session.get(childtbl, epdata['objectId'])
                    except:
                        child = self.session.get(childtbl, epdata['id'])
                    if not child:
                        print('Non-existing child during expansion %s %s: %s' % (dbtype.__table__, expandprop, epdata['objectId']))
                        continue
                    getattr(parent, linkname).append(child)
                    i += 1
                    if i > 1000:
                        self.session.commit()
                        i = 0
        self.session.commit()

    async def dump_keycredentials(self, objecttype, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        cache = []
        from sqlalchemy import inspect
        table = inspect(dbtype)
        
        try:
            url = 'https://graph.microsoft.com/v1.0/%s?$select=keyCredentials,objectId' % (objecttype)
        except:
            url = 'https://graph.microsoft.com/v1.0/%s?$select=keyCredentials,id' % (objecttype)

        # url = 'https://graph.microsoft.com/v1.0/%s?$select=keyCredentials,objectId' % (objecttype)
        
        async for obj in dumphelper(url, method=method):
            try:
                cache.append({'userid':obj['objectId'], 'keyCredentials':obj['keyCredentials']})
            except:
                cache.append({'userid':obj['id'], 'keyCredentials':obj['keyCredentials']})
            finally:
                print("[-] No KeyCredentials returned")
                break

            if len(cache) > 1000:
                commitmfa(self.session, dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            commitmfa(self.session, dbtype, cache)
        del cache[:]

    async def dump_apps_from_list(self, parents, endpoint, dbtype, ignore_duplicates=True):
        cache = []
        jobs = []
        for parentid in parents:
            url = 'https://graph.microsoft.com/v1.0/%s/%s' % (endpoint, parentid)
            
            jobs.append(self.dump_so_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_each(self, parenttbl, endpoint, dbtype, ignore_duplicates=True):
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.microsoft.com/v1.0/%s/%s' % (endpoint, parent.appId)
            
            jobs.append(self.dump_so_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_custom_role_members(self, dbtype, ignore_duplicates=True):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq \'%s\'' % (parent.id)
            # print(parent.objectId)
            jobs.append(self.dump_lo_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_eligible_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        # for parent in parents:
        url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules'#'https://main.iam.ad.ext.azure.com/api/eligibleRoleAssignments?$filter=roleDefinitionId eq \'%s\'' % (parent.objectId)
        
        jobs.append(self.dump_lo_to_db(url, self.ahsession.get, dbtype, cache))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache)
        self.session.commit()

async def run(args):
    global token, expiretime, headers, totalgroups, totaldevices, dburl
    if 'tenantId' in token:
        tenantid = token['tenantId']
    elif args.tenant:
        tenantid = args.tenant
    else:
        tenantid = 'myorganization'
    expiretime = time.mktime(time.strptime(token['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
    headers = {
        'Authorization': '%s %s' % (token['tokenType'], token['accessToken'])
    }
    if args.user_agent:
        # Alias support, get temp auth object
        auth = Authentication()
        auth.set_user_agent(args.user_agent)
        headers['User-Agent'] = auth.user_agent
        # Store this in the token as well
        token['useragent'] = auth.user_agent

    if not checktoken():
        return
    # Recreate DB

    if args.skip_first_phase:
        destroy_db = False
    else:
        destroy_db = True

    engine = database_ibiza.init(destroy_db, dburl=dburl)
    dumper = DataDumper(tenantid, engine=engine)
    post_body = {
        'nextLink': '',
        'putCachedLogoUrlOnly': True,
        'usedFirstPartyAppIds': None,
        'isAppVisible': None,
        'accountEnabled': True,
        'searchText': '',
        'appListQuery': 2, # 0=Enterprise, 1=Microsoft, 2=All
        'loadLogo': False,
        '__ko_mapping__': {
            'copiedProperties': {},
            'include': ['_destroy'],
            'observe': [],
            'mappedProperties': {},
            'copy': [],
            'ignore': []
        },
        'top': 999
    }
    global proxy_config
    proxy_config = {}  
    if args.proxy:
        proxy_config = {
            'proxy': f'{args.proxy_type}://{args.proxy}'
        }

    global disable_verify_switch
    disable_verify_switch = True
    if args.disable_verify:
        disable_verify_switch = False

    if not args.skip_first_phase:
         async with aiohttp.ClientSession() as ahsession:
            
            print('Starting data gathering phase 1 of 2 (collecting objects)')
            dumper.ahsession = ahsession
            # Need to split into two tasks because otherwise the token refresh to msgraph will likely happen at the same time as execution of ibiza tasks which will cause them to fail
            ibizatasks = []
            msgraphtasks = []
            ibizatasks.append(dumper.dump_object('Users?top=999&searchText=', User, method=ahsession.post)) 
            ibizatasks.append(dumper.dump_org_details(TenantDetail))
            ibizatasks.append(dumper.dump_object('Directories/Properties', TenantProperties))
            ibizatasks.append(dumper.dump_conditional_access_policies(Policy))
           
            
            # ----------------- Slow but works -----------------
            # ibizatasks.append(dumper.dump_service_principal_object('ManagedApplications/List', ServicePrincipal, post_body=post_body))
            # ---------------------------------------------------

            # ----------------- Quick but seems to cause issues -----------------
             # Get all SP objects and then we can asynchronously fetch the full details for each individually
            # servicePrincipals = await dumper.dump_service_principal_object('ManagedApplications/List', method=ahsession.post, json_body=post_body)
            
            # for sp in servicePrincipals:
            #     ibizatasks.append(
            #         dumper.dump_service_principal_object(sp, ServicePrincipal)
            #     )
            # ---------------------------------------------------


            ibizatasks.append(dumper.dump_object('Groups?top=999', Group))
            # maybe add dynamic group details https://main.iam.ad.ext.azure.com/api/Groups/__GROUPID__/GetDynamicGroupProperties
            msgraphtasks.append(dumper.dump_object_msgraph('directory/administrativeUnits', AdministrativeUnit)) # Don't see a way to get this information with Ibiza IAM - maybe use Graph? Will just leave it excluded for now as i dont want people to use the ibiza version trying to go undetected thinking there will be no graph requests and then there is some under the hood. 

            msgraphtasks.append(dumper.dump_object_msgraph('applications', Application)) # TO DO: make into Ibiza API req - could do but kind of pointless since graph gives you everything from just listing them
            msgraphtasks.append(dumper.dump_object_msgraph('devices', Device))
            msgraphtasks.append(dumper.dump_object_msgraph('directoryRoles', DirectoryRole))
            msgraphtasks.append(dumper.dump_object_msgraph('roleManagement/directory/roleDefinitions', RoleDefinition))
            # msgraphtasks.append(dumper.dump_object('deviceManagement/roleDefinitions', RoleDefinition)) # possibly interesting? 
            # msgraphtasks.append(dumper.dump_object('domains', Domain))# No class for this yet
            msgraphtasks.append(dumper.dump_object_msgraph('roleManagement/directory/roleAssignments', RoleAssignment))
            msgraphtasks.append(dumper.dump_object_msgraph('contacts', Contact))

            msgraphtasks.append(dumper.dump_object_msgraph('oauth2PermissionGrants', OAuth2PermissionGrant))
            msgraphtasks.append(dumper.dump_object_msgraph('policies/authorizationPolicy', AuthorizationPolicy))
            await asyncio.gather(*ibizatasks)
            await asyncio.gather(*msgraphtasks)

    Session = sessionmaker(bind=engine)
    dbsession = Session()

    if args.skip_first_phase:
        # Delete existing links to make sure we start with clean data
        for table in database_ibiza.Base.metadata.tables.keys():
            if table.startswith('lnk_'):
                dbsession.execute(text("DELETE FROM {0}".format(table)))
        dbsession.query(ApplicationRef).delete()
        dbsession.query(RoleAssignment).delete()
        dbsession.query(EligibleRoleAssignment).delete()
        dbsession.commit()

    # Mapping object, mapping type returned to Table and link name
    group_mapping = {
        'microsoft.graph.user': (User, 'memberUsers'),
        'microsoft.graph.group': (Group, 'memberGroups'),
        'microsoft.graph.contact': (Contact, 'memberContacts'),
        'microsoft.graph.device': (Device, 'memberDevices'),
        'microsoft.graph.serviceprincipal': (ServicePrincipal, 'memberServicePrincipals'),
    }
    group_owner_mapping = {
        'microsoft.graph.user': (User, 'ownerUsers'),
        'microsoft.graph.serviceprincipal': (ServicePrincipal, 'ownerServicePrincipals'),
    }
    owner_mapping = {
        'microsoft.graph.user': (User, 'ownerUsers'),
        'microsoft.graph.serviceprincipal': (ServicePrincipal, 'ownerServicePrincipals'),
    }
    au_mapping = {
        'microsoft.graph.user': (User, 'memberUsers'),
        'microsoft.graph.group': (Group, 'memberGroups'),
        'microsoft.graph.device': (Device, 'memberDevices'),
    }
    role_mapping = {
        'microsoft.graph.user': (User, 'memberUsers'),
        'microsoft.graph.serviceprincipal': (ServicePrincipal, 'memberServicePrincipals'),
        'microsoft.graph.group': (Group, 'memberGroups'),
    }
    # Direct link mapping
    group_link_mapping = {
        'microsoft.graph.user': (lnk_group_member_user, 'Group', 'User'),
        'microsoft.graph.group': (lnk_group_member_group, 'Group', 'childGroup'),
        'microsoft.graph.contact': (lnk_group_member_contact, 'Group', 'Contact'),
        'microsoft.graph.device': (lnk_group_member_device, 'Group', 'Device'),
        'microsoft.graph.serviceprincipal': (lnk_group_member_serviceprincipal, 'Group', 'ServicePrincipal'),
    }
    # au_link_mapping = {
    #     'microsoft.graph.user': (lnk_au_member_user, 'AdministrativeUnit', 'User'),
    #     'microsoft.graph.group': (lnk_au_member_group, 'AdministrativeUnit', 'Group'),
    #     'microsoft.graph.device': (lnk_au_member_device, 'AdministrativeUnit', 'Device'),
    # }
    group_owner_link_mapping = {
        'microsoft.graph.user': (lnk_group_owner_user, 'Group', 'User'),
        'microsoft.graph.serviceprincipal': (lnk_group_owner_serviceprincipal, 'Group', 'ServicePrincipal'),
    }
    device_link_mapping = {
        'microsoft.graph.user': (lnk_device_owner, 'Device', 'User'),
    }


    headers['Authorization'] = '%s %s' % (msgraphToken['tokenType'], msgraphToken['accessToken'])
    tasks = []
    dumper.session = dbsession
    # pylint: disable=not-callable
    totalgroups = dbsession.query(func.count(Group.objectId)).scalar()
    totaldevices = dbsession.query(func.count(Device.id)).scalar()
    if totalgroups > MAX_GROUPS:
        print('Gathered {0} groups, switching to 3-phase approach for efficiency'.format(totalgroups))
    async with aiohttp.ClientSession() as ahsession:
        
        if totalgroups > MAX_GROUPS:
            print('Starting data gathering phase 2 of 3 (collecting properties and relationships)')
        else:
            print('Starting data gathering phase 2 of 2 (collecting properties and relationships)')
        dumper.ahsession = ahsession
        # If we have a lot of groups, dump them separately
        if totalgroups <= MAX_GROUPS:
            tasks.append(dumper.dump_links('groups', 'members', Group, mapping=group_mapping))
            tasks.append(dumper.dump_links('groups', 'owners', Group, mapping=group_owner_mapping))
            # tasks.append(dumper.dump_links('administrativeUnits', 'members', AdministrativeUnit, mapping=au_mapping))
            tasks.append(dumper.dump_object_expansion('devices', Device, 'registeredOwners', 'owner', User))
        tasks.append(dumper.dump_links('directoryRoles', 'members', DirectoryRole, mapping=role_mapping))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignedTo', ServicePrincipal, AppRoleAssignmentto, ignore_duplicates=True))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignments', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion('servicePrincipals', ServicePrincipal, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_object_expansion('applications', Application, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_custom_role_members(RoleAssignment))
        tasks.append(dumper.dump_eligible_role_members(EligibleRoleAssignment))
        if args.mfa:
            tasks.append(dumper.dump_mfa(User, method=ahsession.get))
        # tasks.append(dumper.dump_each(ServicePrincipal, 'applicationRefs', ApplicationRef)) # Doesn't look like new graph has a direct alternative API available
        tasks.append(dumper.dump_keycredentials('servicePrincipals', ServicePrincipal))
        tasks.append(dumper.dump_keycredentials('applications', Application))
        await asyncio.gather(*tasks)
    dbsession.commit()

    tasks = []
    if totalgroups > MAX_GROUPS:
        print('Starting data gathering phase 3 of 3 (collecting group memberships and device owners)')
        async with aiohttp.ClientSession() as ahsession:
           
            dumper.ahsession = ahsession
            queue = asyncio.Queue(maxsize=100)
            # Start the workers
            workers = []
            for i in range(100):
                workers.append(asyncio.ensure_future(queue_processor(queue)))

            tasks.append(dumper.dump_links_with_queue(queue, 'devices', 'registeredOwners', Device, mapping=device_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'members', Group, mapping=group_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'owners', Group, mapping=group_owner_link_mapping))
            # tasks.append(dumper.dump_links_with_queue(queue, 'administrativeUnits', 'members', AdministrativeUnit, mapping=au_link_mapping))

            await asyncio.gather(*tasks)
            await queue.join()
            for worker_task in workers:
                worker_task.cancel()

    dbsession.commit()
    dbsession.close()

# def getargs(gather_parser):
#     gather_parser.add_argument('-d', '--database', action='store',
#                               help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools. Default: roadrecon.db',
#                               default='roadrecon.db')
#     gather_parser.add_argument('-f', '--tokenfile', action='store',
#                               help='File to read credentials from obtained by roadrecon auth',
#                               default='.roadtools_auth')
#     gather_parser.add_argument('--tokens-stdin', action='store_true',
#                               help='Read tokens from stdin instead of from disk')
#     gather_parser.add_argument('--mfa', action='store_true',
#                               help='Dump MFA details (requires use of a privileged account)')
#     gather_parser.add_argument('--skip-first-phase', action='store_true',
#                               help='Skip the first phase (assumes this has been previously completed)')
#     gather_parser.add_argument('-t', '--tenant',
#                               action='store',
#                               help='Tenant objectId to gather, if this info is not stored in the token')
#     gather_parser.add_argument('-ua', '--user-agent', action='store',
#                               help='Custom user agent to use. By default aiohttp default user agent is used, and python-requests is used for token renewal')
#     gather_parser.add_argument('-p', '--proxy', action='store',
#                               help='Proxy server address (e.g., http://proxy.example.com:8080)')
#     gather_parser.add_argument('--proxy-type', action='store', default='http',
#                               help='Proxy type (http, https, socks5, etc.)')



def main(args=None):
    global token, headers, dburl, urlcounter, tokendata, refreshToken
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='roadrecon - Gather Entra objectId information',
                                         formatter_class=argparse.RawDescriptionHelpFormatter)
        # getargs(parser)
        args = parser.parse_args()
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    if args.tokens_stdin:
        token = json.loads(sys.stdin.read())
    else:
        with open(args.tokenfile, 'r') as infile:
            token = json.load(infile)
    if not ':/' in args.database:
        if args.database[0] != '/':
            dburl = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            dburl = 'sqlite:///' + args.database
    else:
        dburl = args.database
    try:
        _, tokendata = Authentication.parse_accesstoken(token['accessToken'])
    except KeyError:
        print('No access token found in tokenfile')
        return
    
    try:
        refreshToken = token['refreshToken']
    except KeyError:
        print('No refresh token found in tokenfile')
        return

    if tokendata['appid'] not in ("c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "04b07795-8ddb-461a-bbee-02f9e1bf7b46"):
        try:
            print(f"[WARNING] Client is {tokendata['app_displayname']}: {tokendata['appid']} for best results use Azure Portal: c44b4083-3bb0-49c1-b47d-974e53cbdf3c or Azure CLI: 04b07795-8ddb-461a-bbee-02f9e1bf7b46")
        except:
            print(f"[WARNING] Client is {tokendata['appid']} for best results use Azure Portal: c44b4083-3bb0-49c1-b47d-974e53cbdf3c or Azure CLI: 04b07795-8ddb-461a-bbee-02f9e1bf7b46")
    if tokendata['aud'] not in ('https://main.iam.ad.ext.azure.com', 'https://main.iam.ad.ext.azure.com/', '74658136-14ec-4630-ad9b-26e160ff0fc6'):
        print(f"Wrong token audience, got {tokendata['aud']} but expected 74658136-14ec-4630-ad9b-26e160ff0fc6")
        print("Make sure to request a token with -r 74658136-14ec-4630-ad9b-26e160ff0fc6. Remember this resource only supports authorization code flow")
        return
    headers['Authorization'] = f"Bearer {token['accessToken']}"

    seconds = time.perf_counter()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(args))
    elapsed = time.perf_counter() - seconds
    print("roadrecon gather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))



if __name__ == "__main__":
    main()
