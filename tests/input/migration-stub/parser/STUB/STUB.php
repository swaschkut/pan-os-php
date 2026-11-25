<?php
/** stand-in vendor parser of the tests: every "permit" / "deny" line of the file becomes one security rule */
class STUBPARSER extends PARSER
{
    public function rules( string $text ): array
    {
        $rules = array();
        foreach( preg_split( '/\R/', $text ) as $line )
            if( preg_match( '/^\s*(permit|deny)\s/', $line, $m ) )
                $rules[] = $m[1] === 'permit' ? 'allow' : 'deny';
        return $rules;
    }
}
