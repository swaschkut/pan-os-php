<?php

class FilePutContents
{
    public static function putContents($filename, $content, $FILE_APPEND = FALSE): void
    {
        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;
        if( PanAPIConnector::$projectfolder !== "" )
            $filename = PanAPIConnector::$projectfolder."/".$filename;

        if( $FILE_APPEND )
            file_put_contents($filename, $content, FILE_APPEND);
        else
            file_put_contents($filename, $content);
    }

}