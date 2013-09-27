package org.nick.passman;

public class PasswordEntry {

    private Long id;
    private String name;
    private String encryptedPasswod;

    public PasswordEntry(String name, String encryptedPassword) {
        this.name = name;
        this.encryptedPasswod = encryptedPassword;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public String getEncryptedPasswod() {
        return encryptedPasswod;
    }

    @Override
    public String toString() {
        return String.format("PasswordEntry[%s %s]", id, name);
    }

}
