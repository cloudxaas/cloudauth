#!/usr/bin/python3

"""

<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="identifier_1"
    Version="2.0"
    IssueInstant="2004-12-05T09:21:59Z"
    AssertionConsumerServiceIndex="1">
    <!-- TODO: how to request attributes assertion -->
    <saml:Subject>
        <saml:NameID Format="app@host#user">app@host#user</saml:NameID>
        <!-- info on how subject is verified: transport or key/challenge  -->
        <saml:SubjectConfirmation
           Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
           <saml:SubjectConfirmationData Address="host fqdn or ip">
		<ds:KeyInfo></ds:KeyInfo>
           </saml:SubjectConfirmationData>
        </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:NameIDPolicy
        AllowCreate="false"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>

    <saml:Conditions
        NotBefore="2005-01-31T12:00:00Z"
        NotOnOrAfter="2005-01-31T12:10:00Z">

        <saml:OneTimeUse/>

        <!-- who can proxy this assertion -->
        <saml:ProxyRestriction count="1">
            <saml:Audience>https://px.example.com/SAML2</saml:Audience>
        </saml:ProxyRestriction>
        <!-- who this assertion is intended -->
        <saml:AudienceRestriction>
           <saml:Audience Format="app@host#user">srvs-a@jzsrv.y.c#jz</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    
    <samlp:Extensions>
        <saml:AttributeStatement>
            <saml:Attribute Name="binary">
                <!-- first one is the "main" executable, modules afterwards -->
                <saml:AttributeValue xsi:type="xs:string" subname="path2binary"/>
            </saml:Attribute>

            <saml:Attribute Name="rt-ctx">
                <saml:AttributeValue xsi:type="xs:string" Name="bin-dir"/>
                <saml:AttributeValue xsi:type="xs:string" Name="cmdargs"/>
                <saml:AttributeValue xsi:type="xs:string" Name="exe_cwd"/>
                <saml:AttributeValue xsi:type="xs:string" Name="exe_root"/>
                <saml:AttributeValue xsi:type="xs:string" Name="env:env1"/>
                <saml:AttributeValue xsi:type="xs:string" Name="env:env2"/>
            </saml:Attribute>

            <saml:Attribute Name="app-ctx">
                <saml:AttributeValue xsi:type="xs:string" Name="ctx-name1"/>
                <saml:AttributeValue xsi:type="xs:string" Name="ctx-name2"/>
            </saml:Attribute>

            <saml:Attribute Name="sys-ctx">
                <saml:AttributeValue xsi:type="xs:string" Name="ctx-name1"/>
                <saml:AttributeValue xsi:type="xs:string" Name="ctx-name2"/>
            </saml:Attribute>

            <saml:Attribute Name="roles">
                <!--rolename is preferrably service scoped, or only return
                    roles applicable to a service. 
                    due to need-to-know, for each service listed below, there
                    will be a seperate "assertion", i.e. auth_token returned. 
                -->
                <saml:AttributeValue xsi:type="xs:string" Name="serviceid">service1</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string" Name="serviceid">service2</saml:AttributeValue>
            </saml:Attribute>
   
        </saml:AttributeStatement>

    </samlp:Extensions>

</samlp:AuthnRequest>

<saml:Assertion xmlns:saml=”urn:oasis:names:tc:SAML:2.0:assertion”
    ID="b07b804c-7c29-ea16-7300-4f3d6f7928ac"
    Version="2.0"
    IssueInstant="2005-01-31T12:00:00Z">
    
    <saml:Issuer Format="app@host#user">https://idp.y.c/</saml:Issuer>

    <!-- signature of the assertion -->
    <ds.Signature>....</ds.Signature>
    
    <saml:Subject>
        <saml:NameID Format="app@host#user">app@host#user</saml:NameID>
        <!-- info on how subject is verified: transport or key/challenge  -->
        <saml:SubjectConfirmation
           Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
           <saml:SubjectConfirmationData Address="host fqdn or ip">
		<ds:KeyInfo></ds:KeyInfo>
           </saml:SubjectConfirmationData>
        </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions
        NotBefore="2005-01-31T12:00:00Z"
        NotOnOrAfter="2005-01-31T12:10:00Z">

        <saml:OneTimeUse/>

        <!-- who can proxy this assertion -->
        <saml:ProxyRestriction count="1">
            <saml:Audience>https://px.example.com/SAML2</saml:Audience>
        </saml:ProxyRestriction>
        <!-- who this assertion is intended -->
        <saml:AudienceRestriction>
           <saml:Audience Format="app@host#user">srvs-a@jzsrv.y.c#jz</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement
        AuthnInstant="2005-01-31T12:00:00Z">
        <saml:SubjectLocality Address="1.1.1.1" DNSName="jz.yahoo.com"/>
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        <saml:AuthenticatingAuthority/>
        </saml:AuthenticatingAuthority>
        </saml:AuthnContext>
    </saml:AuthnStatement>

    <saml:AttributeStatement>
    
        <!-- here we have roles and attributes like binary-hash, env, args, etc -->

        <saml:Attribute Name="binary">
            <!-- first one is the "main" executable, modules afterwards -->
            <saml:AttributeValue xsi:type="xs:string" subname="path2binary">hash_value1</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="rt-ctx">
            <saml:AttributeValue xsi:type="xs:string" Name="bin-dir">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" Name="cmdargs">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" Name="exe_cwd">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" Name="exe_root">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" Name="env:env1">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" Name="env:env2">......</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="app-ctx">
            <saml:AttributeValue xsi:type="xs:string" Name="ctx-name">ctx_value</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="sys-ctx">
            <saml:AttributeValue xsi:type="xs:string" Name="ctx-name">ctx_value</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="roles">
            <saml:AttributeValue xsi:type="xs:string">{servicename}.admin</saml:AttributeValue>
        </saml:Attribute>

   </saml:AttributeStatement>

</saml:Assertion>

"""
