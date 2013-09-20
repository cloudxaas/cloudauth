#!/usr/bin/python3

"""

<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="identifier_1"
    Version="2.0"
    IssueInstant="2004-12-05T09:21:59Z"
    AssertionConsumerServiceIndex="1">

    <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
    <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
</samlp:AuthnRequest>

<saml:Assertion xmlns:saml=”urn:oasis:names:tc:SAML:2.0:assertion”
    ID="b07b804c-7c29-ea16-7300-4f3d6f7928ac"
    Version="2.0"
    IssueInstant="2005-01-31T12:00:00Z">
    
    <saml:Issuer>https://idp.y.c/</saml:Issuer>

    <!-- signature of the assertion -->
    <ds.Signature>....</ds.Signature>
    
    <saml:Subject>
        <saml:NameID>app@host#user</saml:NameID>
        <!-- info on how subject is verified -->
        <saml:SubjectConfirmation
           Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
           <saml:SubjectConfirmationData
                InResponseTo="aaf23196-1773-2113-474a-fe114412ab72"
                Recipient="https://sp.example.com/SAML2/SSO/POST"
                NotOnOrAfter="2004-12-05T09:27:05"
                Address="host fqdn or ip"/>
        </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions
        NotBefore="2005-01-31T12:00:00Z"
        NotOnOrAfter="2005-01-31T12:10:00Z">
        <!-- who can proxy this assertion -->
        <saml:ProxyRestriction>
            <saml:Audience>https://px.example.com/SAML2</saml:Audience>
        </saml:ProxyRestriction>
        <!-- who this assertion is intended -->
        <saml:AudienceRestriction>
           <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement
        AuthnInstant="2005-01-31T12:00:00Z" SessionIndex="67775277772">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>

    <saml:AttributeStatement>
    
        <!-- here we have roles and attributes like binary-hash, env, args, etc -->

        <saml:Attribute Name="binary">
            <!-- first one is the "main" executable, modules afterwards -->
            <saml:AttributeValue xsi:type="xs:string" subname="path2binary">hash_value1</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="rt-ctx">
            <saml:AttributeValue xsi:type="xs:string" subname="bin-dir">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" subname="cmdargs">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" subname="exe_cwd">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" subname="exe_root">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" subname="env:env1">......</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string" subname="env:env2">......</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="app-ctx">
            <saml:AttributeValue xsi:type="xs:string" subname="ctx-name">ctx_value</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="sys-ctx">
            <saml:AttributeValue xsi:type="xs:string" subname="ctx-name">ctx_value</saml:AttributeValue>
        </saml:Attribute>

        <saml:Attribute Name="roles">
            <saml:AttributeValue xsi:type="xs:string">{servicename}.admin</saml:AttributeValue>
        </saml:Attribute>

   </saml:AttributeStatement>

</saml:Assertion>

"""
