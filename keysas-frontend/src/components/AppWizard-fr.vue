<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
      <section id="no-signed-key">
<h1>Félicitations et bienvenue sur <b>Keysas</b></h1>
<p> Mon ip est {{ ip[0] }}.</p>
<div class="callout callout-info">
Si c'est la première fois que vous utilisez la station blanche <b>Keysas</b>, vous devez commencer par signer un périphérique USB de sortie. <br>
Ce tutoriel va vous montrer coment procéder. Vous pourrez le ré-afficher à tout moment en utilisant le menu en haut à droite.
</div>
<h2>Comment créer un périphérique USB de sortie ?</h2>
<section id="connexion-a-la-station-blanche">
<h3>1 - Utilisez Keysas-admin</h3>
<p>L’image fournie est basée sur une distribution GNU/Linux Debian 12 (Bookworm) durcie. Le DHCP est activé par défaut: l’adresse IP obtenue est normalement affichée plus haut.</p>
<p>Afin de prémunir la station blanche d’attaques de type BadUSB, seuls les périphériques USB de type “stockage de masse” comme les clés ou disques durs USB sont reconnus par la station blanche. Les claviers USB et les souris ne peuvent donc pas fonctionner.</p>
<div class="callout callout-info">
Pour signer un périphérique USB de sortie, vous devez d'abord télécharger et installer l'application <b>keysas-admin</b> depuis le site keysas.fr et vous référez à la documentation de l'application. Cette application est pour le moment uniquement disponible 
au format <i>.deb</i> et <i>.appimage</i> (GNU/Linux) et .msi (Windows).
</div> 

</section>
<section id="generation-des-cles-de-signature">
<h3>2 - Génération de la PKI de signature</h3>
<p>Pour signer les périphériques USB de confiance et pour que la station blanche puisse signer les rapports d'analyse, vous devez créer une <b>IKPQPKI</b> depuis <b>Keysas-admin</b></p>
<p>Allez dans le menu d'administration puis cliquez sur <b>IKPQPKI</b> et créer une nouvelle <b>IKPQPKI</b></p>

<div class="callout callout-warning">
Le mot de passe de cette PKI doit être suffisement complexe et il conviendra de le sauvegarder en suivant les recommendations en vigueur.<br>
Toute perte de ce mot de passe rendra la PKI définitivement inutilisable.
</div>
<div class="callout callout-danger">
Par défaut, les clés privées sont stockées au format <b>PKCS#8</b> et les clés publiques au format PEM. <br>
Sur les stations blanches, l'ensemble des clés sont enregistrées dans /etc/keysas/.
</div>
</section>
<section id="signature-d-un-peripherique-usb">
<h3>3 - Signature d’un périphérique USB</h3>
<p>Une fois la paire de clés correctement générée, éxecutez la commande suivante:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign --watch</span>
</code></pre></div>
<p>Brancher maintenant le périphérique usb de sortie à signer sur la station blanche. Ce périphérique devra être vide de tout fichier afin d’éviter des transferts non désirés.</p>
<p>Pressez Ctrl+C et copier/coller la ligne qui apparait dans le terminal en la modifiant avec le mot de passe que
vous avez choisi pour générer la paire de clés précédemment. Par exemple:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign -device=/dev/sda --sign --password=Toto007 --vendorid=0951 --modelid=160b --revision=1.00 --serial=Kingston_DataTraveler_2.0_0019E000B4625C8B0A070016-0:0</span>
</code></pre></div>
<p>Le nouveau périphérique USB devrait être maintenant correctement signé et formaté en fat32. Vous pouvez bien entendu reformater le périphérique avec tout autre système de fichier supporté par la station blanche (ext2, ext3, ext4, fat32, exfat, ntfs)</p>
<div class="callout callout-info">
Répetez cette procédure avec l’ensemble des périphériques USB que vous souhaitez utiliser en tant que périphériques de sortie.
</div>
<p>Une fois l’opération terminée, débranchez le(s) périphérique’s) et rebranchez-le(s) afin de s’assurer qu’il(s) est(sont) bien reconnu(s) comme périphérique(s) de sortie.</p>
<p>Pour plus de documentation, rendez-vous sur <b>keysas.fr</b>.</p>
</section>
</section>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "AppWizard-fr",
  props: {
    ip: [],
  },
};
</script>

<style lang="scss">
@import "../assets/style/app.scss";

pre {
  background: $navy;
  color: $grey-light;
  padding: 5px;
  border-radius: 2px;
}

#no-signed-key {
  padding: 40px;
}

</style>
