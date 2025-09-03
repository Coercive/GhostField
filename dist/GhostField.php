<?php
namespace Coercive\Security\GhostField;

use DateTime;

/**
 * Ghost Honeypot Fields handler
 *
 * Provides a multi-layered anti-bot protection system for HTML forms.
 *
 * Main features:
 * - Honeypot fields: injects invisible trap inputs that, if filled, indicate bot activity.
 * - Field name obfuscation: replaces human-readable field names with unpredictable hashes.
 * - Optional JavaScript proof: requires client-side JS to populate a hidden verification field,
 *   preventing most non-JS bots from submitting valid forms.
 *
 * This class is designed to complement existing security measures by reducing
 * automated spam without adding friction for legitimate users.
 *
 * Note: While effective against simple and medium-level bots, this system should
 * not be considered a substitute for server-side validation, CAPTCHA, or other
 * advanced anti-abuse mechanisms.
 *
 * @package Coercive\Security\GhostField
 * @link https://github.com/Coercive/GhostField
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright © 2025 Anthony Moral
 * @license MIT
 *
 * - - - - - - - -
 *
 * Helping Sources
 *
 * How To Stop Form Bots With Honeypot Fields
 * @author Jeff Jakinovich
 * @link https://dev.to/jeffbuildstech/how-to-stop-form-bots-with-honeypot-fields-8od
 *
 * Honeypots in Web Forms: Smart Spam Protection Without Compromising UX
 * @author Kartheek Desineedi
 * @link https://kdesineedi.medium.com/honeypots-in-web-forms-smart-spam-protection-without-compromising-ux-2f62cf0f6f41
 *
 * Stopping spambots with hashes and honeypots
 * @author Ned Batchelder
 * @link https://nedbatchelder.com/text/stopbots.html
 *
 * Restricting automated spam submissions in web forms
 * @author Torben Hansen
 * @link https://www.derhansen.de/2022/07/restricting-automated-spam-submissions-in-web-forms.html
 */
class GhostField
{
    const DEFAULT_SIGIL_NAME = 'sigil';

	/**
	 * bool $legit, string $name, string $type = '', string $placeholder = ''
	 */
    const DEFAULT_FIELDS = [
		[false, 'csrf_token', 'text', 'securized timestamp token'],
		[false, 'internal_reference', 'number', 'User subscriber number'],
		[false, 'order_date', 'date', 'Date of order'],
		[false, 'user_date_of_birth', 'date', 'User date of birth'],
		[false, 'user_subscriber_number', 'text', 'User subscriber number'],
		[false, 'user_gender', 'text', 'User gender [male/female]'],
		[false, 'user_first_name', 'text', 'User first name'],
		[false, 'user_last_name', 'text', 'User last name'],
		[false, 'user_middle_name', 'text', 'User middle name'],
		[false, 'user_company', 'text', 'User company name'],
		[false, 'user_email', 'email', 'User email'],
		[false, 'user_password', 'password', 'User password'],
		[false, 'user_password_confirm', 'password', 'User confirm password'],
		[false, 'user_address', 'text', 'User main address'],
		[false, 'user_city', 'text', 'User address city'],
		[false, 'user_zip', 'text', 'User address zip code'],
		[false, 'user_country', 'text', 'User address country'],
		[false, 'user_phone_number', 'phone', 'User phone number'],
		[false, 'user_fax_number', 'phone', 'User fax number'],
		[false, 'user_mobile_number', 'phone', 'User mobile phone number'],
		[false, 'user_linkedin_url', 'text', 'User LinkedIn Account'],
		[false, 'user_facebook_url', 'text', 'User Facebook Account'],
		[false, 'user_twitter_url', 'text', 'User Twitter/X Account'],
		[false, 'user_bluesky_url', 'text', 'User Bluesky Account'],
		[false, 'user_youtube_url', 'text', 'User YouTube Account'],
		[false, 'search_query', 'text', 'Search query'],
		[false, 'input_title', 'text', 'Selected title'],
		[false, 'input_recipient', 'text', 'Selected recipient'],
		[false, 'input_message', 'text', 'Your message here'],
		[false, 'promotional_code', 'text', 'Set your promotional code here if needed'],
		[false, 'sms_code_confirm', 'text', 'A code from SMS mobile phone number check'],
		[false, 'rgpd_accept', 'checkbox', 'Accept the use of personal data'],
		[false, 'third_party_cookies_accept', 'checkbox', 'Accept the use of third-party cookies'],
		[false, 'adult_confirm', 'checkbox', 'Are you an adult (confirm 18+)'],
	];

	private string $sigilName = '';
	private string $sigilTime = '';

	private string $key;

	private DateTime $now;
	private string $timestamp;

	/** @var Field[] */
	private array $fields = [];

	/**
	 * Generates an obfuscated and unique field name for form inputs.
	 *
	 * The generated name is deterministic and based on:
	 * - the original field name,
	 * - a secret application key,
	 * - and a timestamp (defaults to the current instance hour-timestamp).
	 *
	 * The result is prefixed with "ID" and followed by a SHA-512 hash, making it
	 * extremely difficult for automated bots to predict or reuse field names.
	 *
	 * @param string $name
	 * @param string $timestamp [optional]
	 * @return string
	 */
	private function randomName(string $name, string $timestamp = ''): string
	{
        $timestamp = $timestamp ?: $this->timestamp;
		return 'ID' . hash('sha512', $name . '_' . $this->key . $timestamp);
	}

	/**
     * Computes the 32-bit FNV-1a hash of a given string.
	 *
	 * This implementation processes the string as a sequence of UTF-8 bytes
	 * to ensure consistent results across different platforms (e.g. PHP vs JS).
	 * The output is returned as an 8-character hexadecimal string.
	 *
	 * Note: FNV-1a is a non-cryptographic hash function. It is fast and suitable
	 * for lightweight integrity checks, obfuscation, or hash-based lookups,
	 * but should not be used for cryptographic security purposes.
     *
	 * @param string $str
	 * @return string
	 */
	private function fnv1a32(string $str): string
    {
		$hash = 0x811c9dc5;
		$len = strlen($str);
		for ($i = 0; $i < $len; $i++) {
			$hash ^= ord($str[$i]);
			$hash = ($hash * 0x01000193) & 0xFFFFFFFF;
		}
		return str_pad(dechex($hash), 8, '0', STR_PAD_LEFT);
	}

	/**
     * GhostField constructor.
     *
	 * @param string $key Used to obfuscate field names
	 * @param DateTime|null $now [optional] Use your own date, with jetlags...
     * @return void
	 */
	public function __construct(string $key, ? DateTime $now = null)
	{
		$this->key = $key;
        $this->now = $now ?: new DateTime;
        $this->timestamp = $this->now->format('Y-m-d H');
	}

	/**
     * Enables the JavaScript verification field used as an additional anti-bot measure.
	 *
	 * When this feature is enabled, the form includes a hidden input that must be
	 * populated client-side by JavaScript. The browser computes a hash value
	 * (based on the user-agent string and a timestamp) and injects it into the
	 * hidden field before submission.
	 *
	 * On form validation, the server recomputes the expected hash and verifies
	 * that the submitted value matches. This ensures that:
	 * - the client has executed JavaScript (most basic bots will fail),
	 * - the submission is tied to the current user-agent and timeframe,
	 * - replay or pre-filled submissions without JS are rejected.
	 *
	 * This mechanism is not intended as a standalone protection, but as a
	 * complementary layer to honeypots and field obfuscation.
     *
	 * @param string $name [optional]
	 * @return $this
	 */
    public function setSigil(string $name = self::DEFAULT_SIGIL_NAME): self
	{
        if(!$this->sigilName) {
            $this->sigilName = $name;
            $this->sigilTime = sha1($this->now->getTimestamp());
            $this->createField(false, $name . '_time', 'hidden')
                ->setValue($this->sigilTime)
                ->setSigil(true);
            $this->createField(false, $name, 'hidden')
                ->setValue(uniqid('tck_'))
                ->setSigil(true);
        }
        return $this;
    }

	/**
	 * @param Field[] $fields
	 * @return $this
	 */
    public function addFields(array $fields): self
	{
		foreach ($fields as $field) {
			$this->addField($field);
		}
		return $this;
    }

	/**
	 * @param Field $field
	 * @return $this
	 */
	public function addField(Field $field): self
	{
        if($n = $field->getName()) {
            $this->fields[$n] = $field;
        }
        return $this;
	}

	/**
	 * @param array $fields [optional]
	 * @return $this
	 */
	public function createFields(array $fields = self::DEFAULT_FIELDS): self
	{
		foreach ($fields as $field) {
            if(is_array($field)) {
				$b = is_bool($field[0]);
				$legit = $b ? $field[0] : true;
				$name =  $field[$b ? 1 : 0] ?? '';
				$type =  $field[$b ? 2 : 1] ?? '';
				$placeholder =  $field[$b ? 3 : 2] ?? '';
            }
			else {
				$legit = true;
				$name = $field;
				$type = '';
				$placeholder = '';
			}
			$this->createField($legit, $name, $type, $placeholder);
		}
		return $this;
	}

	/**
     * Add a HTML field, build with a label wrap arround, a name, a type.
     *
	 * @param bool $legit The field is legeit, else it's a honeypot
	 * @param string $name
	 * @param string $type [optional]
	 * @param string $placeholder [optional]
	 * @return Field|null
	 */
    public function createField(bool $legit, string $name, string $type = '', string $placeholder = ''): ? Field
	{
		if(!preg_match('`^[a-z\d_-]+$`i', $name)) {
			return null;
		}
		return $this->fields[$name] = (new Field)
            ->setLegit($legit)
            ->setId($this->randomName($name))
            ->setName($name)
            ->setType($type)
            ->setPlaceholder($placeholder);
    }

	/**
	 * @return Field[]
	 */
	public function getFields(): array
	{
		return $this->fields;
	}

	/**
     * @param string $name
	 * @return Field|null
	 */
	public function getField(string $name): ? Field
	{
		return $this->fields[$name] ?? null;
	}

	/**
     * @see createField()
	 * @param string $name
	 * @param string $type [optional]
	 * @param string $placeholder [optional]
	 * @return $this
	 */
	public function addLegit(string $name, string $type = '', string $placeholder = ''): self
	{
        $this->createField(true, $name, $type, $placeholder);
		return $this;
	}

	/**
     * @see createField()
	 * @param string $name
	 * @param string $type [optional]
	 * @param string $placeholder [optional]
	 * @return $this
	 */
	public function addHoneypot(string $name, string $type = '', string $placeholder = ''): self
	{
		$this->createField(false, $name, $type, $placeholder);
		return $this;
	}

	/**
	 * @param string $name
	 * @return string
	 */
	public function getId(string $name): string
	{
        if($field = $this->getField($name)) {
            return $field->getId();
        }
		return '';
	}

	/**
     * Automatically generate trapped form fields
     *
	 * @return string
	 */
	public function getHtmlHoneypots(): string
	{
		ob_start();
		foreach($this->fields as $field):
            if($field->isLegit()) { continue; }
            if($field->getType() !== 'hidden'): ?>
                <label id="<?= $field->getId() ?>">
                    <?= $field->getName() ?>
                    <input type="<?= $field->getType() ?>" name="<?= $field->getId() ?>" title="<?= $field->getPlaceholder() ?>" placeholder="<?= $field->getPlaceholder() ?>" value="<?= $field->getValue() ?>" autocomplete="off" required tabindex="-1" /><?php
            else: ?>
                <input type="hidden" name="<?= $field->getId() ?>" value="<?= $field->getValue() ?>" /><?php
            endif;
			if($field->getType() !== 'hidden'): ?>
                </label><?php
			endif;
		endforeach;
		return ob_get_clean();
	}

	/**
     * Filter the legit data from inputs
     *
	 * @param array $input
	 * @return array
	 */
    public function getData(array $input): array
	{
        $data = [];

		foreach ($this->fields as $field) {
			if(!$field->isLegit()) {
				continue;
			}
			if (array_key_exists($field->getId(), $input)) {
				$data[$field->getName()] = $input[$field->getId()];
			}
		}

        if(!$data) {
			$adjusted = (clone $this->now)->modify('-3600 seconds');
			if ($adjusted->format('Y-m-d H') !== $this->now->format('Y-m-d H')) {
				$timestamp = $adjusted->format('Y-m-d H');
				foreach ($this->fields as $field) {
					if(!$field->isLegit()) {
						continue;
					}
					$obfuscated = $this->randomName($field->getName(), $timestamp);
					if (array_key_exists($obfuscated, $input)) {
						$data[$field->getName()] = $input[$obfuscated];
					}
				}
			}
		}

        return $data;
	}

	/**
     * Check if the form contains bad inputs, and if the JS handshake is completed.
     *
	 * @param array $data
	 * @return bool
	 */
	public function validate(array $data): bool
	{
        $sigilTime = null;
        $sigilStamp = null;
		$timestamps = [];

        # Add previous hour timestamp token if needed
		$timestamps[] = $this->now->format('Y-m-d H');
		$adjusted = (clone $this->now)->modify('-3600 seconds');
		if ($adjusted->format('Y-m-d H') !== $this->now->format('Y-m-d H')) {
			$timestamps[] = $adjusted->format('Y-m-d H');
		}

        # Check all trapped fields
		foreach ($timestamps as $timestamp) {
			foreach ($this->fields as $field) {
				if($field->isLegit()) {
					continue;
				}
				$obfuscated = $this->randomName($field->getName(), $timestamp);
				if($field->isSigil() && (!$sigilTime || !$sigilStamp)) {
					if($field->getName() === $this->sigilName . '_time') {
						$sigilTime = $data[$obfuscated] ?? '';
					}
                    elseif($field->getName() === $this->sigilName) {
						$sigilStamp = $data[$obfuscated] ?? '';
					}
					continue;
				}
				if (!empty($data[$obfuscated])) {
					return false;
				}
			}
		}

        # Check input JS calculated sigil
        if($this->sigilName) {
            if(!$sigilTime || !$sigilStamp) {
                return false;
			}

			$ua = strval($_SERVER['HTTP_USER_AGENT'] ?? '');
            $expected = 'tck_' . $this->fnv1a32($ua . $sigilTime);
            if($expected !== $sigilStamp) {
                return false;
			}
		}

		return true;
	}

	/**
     * Automatically generate JS for trapped form fields
     * Hide fields, remove required attribute
     * JS handshake hashing calculation
     *
	 * @return string
	 */
    public function getHideJS(): string
	{
        ob_start(); ?>
        (function() {
            function fnv1a32(str) {
                let hash = 0x811c9dc5;
                const bytes = (new TextEncoder()).encode(str);
                for (let i = 0; i < bytes.length; i++) {
                    hash ^= bytes[i];
                    hash = Math.imul(hash, 0x01000193);
                }
                return (hash >>> 0).toString(16).padStart(8, '0');
            }
            let label = null;
            let input = null;
            const style = document.createElement('style');
            style.type = 'text/css';<?php
        foreach($this->fields as $field):
			if($field->isLegit()) { continue; } ?>
            style.innerHTML += `#<?= $field->getId() ?> {
                pointer-events: none;
                position: absolute;
                display: block;
                opacity: 0;
                left: -9999px;
                max-width: 0;
                width: 0;
                height: 0;
                max-height: 0;
            }`;
            label = document.getElementById('<?= $field->getId() ?>');
            input = label ? label.querySelector('input') : null;
            if (input) {
                input.required = false;
                input.removeAttribute('required');
            }<?php
            if($field->isSigil() && $field->getName() === $this->sigilName): ?>
                let T = document.querySelector('input[name="<?= $this->getId($this->sigilName . '_time') ?>"]')
                input = document.querySelector('input[name="<?= $field->getId() ?>"]');
                if (T && input) {
                    input.value = 'tck_' + fnv1a32(navigator.userAgent + T.value);
                }<?php
            endif;
		endforeach ?>
            document.head.appendChild(style);
        })();<?php
		return ob_get_clean();
	}
}