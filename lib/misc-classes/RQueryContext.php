<?php

/**
 * Class RQueryContext
 * @ignore
 */
class RQueryContext
{
    public $object;

    public $value;
    public $operator;

    public $isAPI = FALSE;

    public $rQueryObject;

    public $nestedQueries;
    public $cachedSubRQuery;

    public $cachedList;

    public $cachedIP4Mapping;

    public $cachedValueMapping;

    /**
     * The filter's argument as a set (name => TRUE), read once and cached: the lines of the file it names
     * ($fromFile), or its comma-separated values.
     * @return array
     */
    public function cachedNameList( $fromFile )
    {
        if( isset( $this->cachedList ) )
            return $this->cachedList;

        if( $fromFile )
        {
            if( !file_exists( $this->value ) )
                derr( "cannot find file '{$this->value}'", null, FALSE );
            $text = file_get_contents( $this->value );
            if( $text === FALSE )
                derr( "cannot open file '{$this->value}" );
            $lines = explode( "\n", $text );
        }
        else
            $lines = explode( ",", $this->value );

        $list = array();
        foreach( $lines as $line )
        {
            $line = trim( $line );
            if( strlen( $line ) > 0 )
                $list[$line] = TRUE;
        }
        $this->cachedList = $list;
        return $list;
    }

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Tag|Address|Service|Zone
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;

        if( $this->rQueryObject->argumentList !== null )
            $this->value = &$this->rQueryObject->argumentList;
        else
            $this->value = &$this->rQueryObject->argument;

        $this->operator = &$this->rQueryObject->operator;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}