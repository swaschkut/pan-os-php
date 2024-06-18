<?php

TagCallContext::$supportedActions[] = Array(
    'name' => 'name-Rename-appid-toolbox',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;

        $date =  date('Ymd');

        $newName = "appid#activated#".$date;

        if( $object->name() == $newName )
        {
            echo $context->padding." *** SKIPPED : new name and old name are the same\n";
            return;
        }

        echo $context->padding." - new name will be '{$newName}'\n";

        $findObject = $object->owner->find($newName);
        if( $findObject !== null )
        {
            echo $context->padding." *** SKIPPED : an object with same name already exists\n";
            return;
        }
        else
        {
            echo $context->padding." - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);
            echo "OK!\n";
        }

    }
);