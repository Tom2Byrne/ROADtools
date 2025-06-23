from roadtools.roadlib.metadef.basetypes import Edm, Collection

class UsersIncludedSet(object):
    props = {
        'allGuestUsers': Edm.Boolean,
        'roles': Edm.Boolean,
        'usersGroups': Edm.Boolean,
        'roleIds': Collection,
        'externalUsers': Edm.Object,
        'groupIds': Collection,
        'userIds': Collection
    }

class usersV2(object):
    props = {
        'allUsers': Edm.Int32,
        'included': UsersIncludedSet,
        'excluded': UsersIncludedSet
    }


class AppMetadataEntry(object):
    props = {
        'key': Edm.String,
        'value': Edm.Binary,
    }

class AppMetadata(object):
    props = {
        'version': Edm.Int32,
        'data': Collection,
    }