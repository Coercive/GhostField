<?php
namespace Coercive\Security\GhostField;

/**
 * @see GhostField main class
 *
 * @package Coercive\Security\GhostField
 * @link https://github.com/Coercive/GhostField
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright © 2025 Anthony Moral
 * @license MIT
 */
class Field
{
    private bool $sigil = false;

    private bool $legit = false;

    private string $id = '';

    private string $type = 'text';

    private string $name = '';

    private string $placeholder = '';

    private string $value = '';

	/**
	 * @param bool $enable
	 * @return $this
	 */
    public function setSigil(bool $enable): self
	{
        $this->sigil = $enable;
        return $this;
    }

	/**
	 * @return bool
	 */
    public function isSigil(): bool
	{
        return $this->sigil;
    }

	/**
	 * @param bool $legit
	 * @return $this
	 */
    public function setLegit(bool $legit): self
	{
        $this->legit = $legit;
        return $this;
    }

	/**
	 * @return bool
	 */
    public function isLegit(): bool
	{
        return $this->legit;
    }

	/**
	 * @param string $id
	 * @return $this
	 */
    public function setId(string $id): self
	{
        $this->id = $id;
        return $this;
    }

	/**
	 * @return string
	 */
    public function getId(): string
	{
        return $this->id;
    }

	/**
	 * @param string $type
	 * @return $this
	 */
    public function setType(string $type): self
	{
        $this->type = $type ?: 'text';
        return $this;
    }

	/**
	 * @return string
	 */
    public function getType(): string
	{
        return $this->type;
    }

	/**
	 * @param string $name
	 * @return $this
	 */
    public function setName(string $name): self
	{
        $this->name = $name;
        return $this;
    }

	/**
	 * @return string
	 */
    public function getName(): string
	{
        return $this->name;
    }

	/**
	 * @param string $placeholder
	 * @return $this
	 */
    public function setPlaceholder(string $placeholder): self
	{
        $this->placeholder = $placeholder;
        return $this;
    }

	/**
	 * @return string
	 */
    public function getPlaceholder(): string
	{
        return $this->placeholder;
    }

	/**
	 * @param string $val
	 * @return $this
	 */
    public function setValue(string $val): self
	{
        $this->value = $val;
        return $this;
    }

	/**
	 * @return string
	 */
    public function getValue(): string
	{
        return $this->value;
    }
}