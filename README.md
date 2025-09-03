# GhostField
Provides a multi-layered anti-bot protection system for HTML forms

## Get

```
composer require coercive/ghostfield
```

## Basics

Common part (send/receipt)

```php
use  Coercive\Security\GhostField\GhostField;

# Load class, set key
$GhostField = new GhostField('123456abcdef');

# Activate handshake JS (optional)
$GhostField->setSigil();

# Create honeypot fields (empty = automatic)
$GhostField->createFields();

# Add your regular fields
$GhostField->createFields([
    'email',
    'password',
]);
```

Send part

```php
?>

<form method="post" action="/send" autocomplete="off"><?php

    # Auto add honeypot fields
    echo $GhostField->getHtmlHoneypots();

    # Add your regular fields bellow ?>
    <label>
        Email : 
        <input type="email" name="<?= $GhostField->getId('email') ?>" required />
    </label>
    <label>
        Password : 
        <input type="password" name="<?= $GhostField->getId('password') ?>" required />
    </label>
    <button type="submit">Send</button>

</form>

```

Receipt part

```php
use  Coercive\Security\GhostField\GhostField;

if(!$GhostField->validate($_POST)) {
    echo 'Unallowed';
    die;
}
```

At the end of you <body>, export the JS part
```php
if($str = $GhostField->getHideJS()): ?>
    <script type="text/javascript"><?= $str ?></script><?php
endif;
```

## Advanced

You can build your own JS/HTML by exporting fields (object)

```php
use  Coercive\Security\GhostField\GhostField;

foreach ($GhostField->getFields() as $field): ?>
    <label id="<?= $field->getId() ?>">
        <?= $field->getName() ?>
        <input type="<?= $field->getType() ?>" name="<?= $field->getId() ?>" placeholder="<?= $field->getPlaceholder() ?>" />
    </label><?php
endforeach;
```