<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Objects a rule references directly (not through a rule container):
 *   security profile group, security profiles (profile-setting), schedule,
 *   log forwarding profile (log-setting), decryption profile, application of an application override rule.
 *
 * replaceReferencedObject() / API_replaceReferencedObject() let ReferenceableObject::replaceMeGlobally()
 * swap such an object for another one of the same kind (used by the mergers). References are moved
 * from the old to the new object and the rule XML is rewritten.
 */
trait RuleDirectReferences
{
    /**
     * @return bool TRUE if $old was referenced by this rule and is replaced by $new
     */
    public function replaceReferencedObject($old, $new)
    {
        return $this->replaceDirectReference($old, $new, FALSE);
    }

    /**
     * @return bool TRUE if $old was referenced by this rule and is replaced by $new
     */
    public function API_replaceReferencedObject($old, $new)
    {
        return $this->replaceDirectReference($old, $new, TRUE);
    }

    protected function replaceDirectReference($old, $new, $apiMode)
    {
        if( $old === $new || !is_object($old) || !is_object($new) )
            return FALSE;

        $replaced = FALSE;
        $xpathSuffix = null;

        // ---- profile-setting: security profile group or single security profiles
        if( property_exists($this, 'secproftype') )
        {
            if( $this->secproftype == 'group' && $old instanceof SecurityProfileGroup && $this->secprofgroup_obj === $old )
            {
                $this->secprofgroup = $new->name();
                $this->secprofgroup_obj = $new;
                $this->rewriteSecProfXML();
                $replaced = TRUE;
                $xpathSuffix = 'profile-setting';
            }
            elseif( $this->secproftype == 'profile' )
            {
                foreach( $this->secprofProfiles_obj as $type => $profile )
                {
                    if( $profile !== $old )
                        continue;
                    $this->secprofProfiles_obj[$type] = $new;
                    $this->secprofProfiles[$type] = $new->name();
                    $replaced = TRUE;
                }
                if( $replaced )
                {
                    $this->rewriteSecProfXML();
                    $xpathSuffix = 'profile-setting';
                }
            }
        }

        // ---- schedule
        if( !$replaced && property_exists($this, 'schedule') && method_exists($this, 'rewriteSchedule_XML') && $this->schedule === $old )
        {
            $this->schedule = $new;
            $this->rewriteSchedule_XML();
            $replaced = TRUE;
            $xpathSuffix = 'schedule';
        }

        // ---- log forwarding profile (stored by name)
        if( !$replaced && $old instanceof LogProfile && property_exists($this, 'logSetting')
            && $this->logSetting !== FALSE && $this->logSetting === $old->name() )
        {
            $this->logSetting = $new->name();
            DH::createOrResetElement($this->xmlroot, 'log-setting', $new->name());
            $replaced = TRUE;
            $xpathSuffix = 'log-setting';
        }

        // ---- decryption profile (stored by name)
        if( !$replaced && $old instanceof DecryptionProfile && $this instanceof DecryptionRule
            && $this->getDecryptionProfile() === $old->name() )
        {
            $this->setDecryptionProfile( $new->name() );
            $replaced = TRUE;
            $xpathSuffix = 'profile';
        }

        // ---- application override rule: its (custom) application
        if( !$replaced && $old instanceof App && $new instanceof App && $this instanceof AppOverrideRule && $this->_app === $old )
        {
            // like setApplication(), the references are moved below
            $this->_app = $new;
            DH::setDomNodeText( DH::findFirstElementOrCreate('application', $this->xmlroot), $new->name() );
            $replaced = TRUE;
            $xpathSuffix = 'application';
        }

        if( !$replaced )
            return FALSE;

        $old->removeReference($this);
        $new->addReference($this);

        if( $apiMode )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
            {
                $node = DH::findFirstElement($xpathSuffix, $this->xmlroot);
                if( $node !== FALSE )
                    $con->sendEditRequest($this->getXPath() . '/' . $xpathSuffix, DH::dom_to_xml($node, -1, FALSE));
            }
        }

        return TRUE;
    }
}
