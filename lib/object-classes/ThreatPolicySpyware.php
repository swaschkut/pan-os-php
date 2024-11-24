<?php

/**
 * ISC License
 *
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


class ThreatPolicySpyware extends ThreatPolicy
{
    public $checkArray;

    public function __construct($name, $owner)
    {
        parent::__construct($name, $owner);
    }

    public function spyware_define_rule_bp_visibility()
    {
        $this->checkArray['spyware'] = array();
        $this->checkArray['spyware']['rule']['bp']['severity'] = array('any', 'critical', 'high', 'medium');
        $this->checkArray['spyware']['rule']['bp']['action'] = array('reset-both');
        $this->checkArray['spyware']['rule']['bp']['packet-capture'] = array('single-packet', 'extended-capture');
        $this->checkArray['spyware']['rule']['visibility']['severity'] = array('any', 'critical', 'high', 'medium','low','informational');
        $this->checkArray['spyware']['rule']['visibility']['action'] = array('!allow');
    }

    public function spyware_rule_best_practice_new()
    {

    }

    public function spyware_rule_best_practice()
    {
        if( ( in_array( "any", $this->severity )
                || in_array( "critical", $this->severity )
                || in_array( "high", $this->severity )
                || in_array( "medium", $this->severity )
            )
            &&
            (
                $this->action() !== "reset-both"
                || ( $this->packetCapture() != "single-packet" && $this->packetCapture() != "extended-capture" )
            )
        )
            return false;
        else
            return true;
    }

    public function spyware_rule_visibility()
    {
        if( ( in_array( "any", $this->severity )
                || in_array( "critical", $this->severity )
                || in_array( "high", $this->severity )
                || in_array( "medium", $this->severity )
                || in_array( "low", $this->severity )
                || in_array( "informational", $this->severity )
            )
            && $this->action() == "allow"
            #&& ( $this->packetCapture() != "single-packet" && $this->packetCapture() != "extended-capture" )
        )
            return false;
        else
            return true;
    }

    public function spywarepolicy_load_from_domxml( $threatx )
    {
        $this->type = "ThreatPolicySpyware";
        $this->load_from_domxml( $threatx );
    }
}


