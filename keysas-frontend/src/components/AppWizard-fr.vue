<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
      <section id="no-signed-key">
<h1>Félicitations et bienvenue sur <b>Keysas</b> !</h1>
<p> Mon ip est {{ ip[0] }}.</p>
<div class="callout callout-info">
Si c'est la première fois que vous utilisez la station blanche <b>Keysas</b>, vous devez commencer par signer un périphérique USB. <br>
Ce tutoriel va vous montrer coment procéder. Vous pourrez le ré-afficher à tout moment en utilisant le menu en haut à droite.
</div>
<h2>Comment créer un périphérique USB de sortie ?</h2>
<section id="connexion-a-la-station-blanche">
<h3>1 - Connexion à votre Station blanche Keysas</h3>
<p>L’image fournie est basée sur une distribution GNU/Linux Debian 11 (Bullseye) durcie. Le DHCP est activé par défaut: l’adresse IP obtenue est normalement affichée plus haut.</p>
<p>Afin de prémunir la station blanche d’attaques de type BadUSB, seuls les périphériques USB de type “stockage de masse” comme les clés ou disques durs USB sont reconnus par la station blanche. Les claviers USB et les souris ne peuvent donc pas fonctionner.</p>
<div class="callout callout-info">
Pour signer un périphérique USB de sortie, vous pouvez choisir de télécharger l'application <b>keysas-admin</b> sur le site keysas.fr et vous référez à la documentation de l'application. Cette application est pour le moment uniquement disponible 
au format <i>.deb</i> et <i>.appimage</i> (GNU/Linux) et .msi (Windows).
</div> 
<p>Vous pouvez également choisir de vous connecter en utilisant le protocole SSH sur la station blanche:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">ssh keysas-sign@{{ ip[0] }} (IP obtenue via DHCP)</span>
</code></pre></div>
<div class="callout callout-warning">
Le mot de passe par defaut est Changeme. Il conviendra de modifier ce dernier dès la première utilisation en le remplacant par un mot de passe robuste.
</div>
</section>
<section id="generation-des-cles-de-signature">
<h3>2 - Génération des clés de signature</h3>
<p>Pour signer une clé USB "à la main", nous allons d'abord générer une paire de clés asymétriques qui servira à signer et vérifier les périphériques sortants:</p>
<div class="highlight"><pre><code class="language-html" data-lang="html"><span></span><span class="go">sudo /usr/bin/keysas-sign --generate --password=Toto007</span>
<span class="go">sudo chmod 600 /etc/keysas/keysas.priv</span>
<span class="go">sudo chattr +i /etc/keysas/keysas.priv</span>
</code></pre></div>
<div class="callout callout-warning">
Il est très important de remplacer le mot de passe dans la ligne de commande par le votre :)<br>
Ce mot de passe sera nécessaire pour chaque signature d'un nouveau périphérique USB.
</div>
<div class="callout callout-danger">
Cette bi-clé doit être générée une seule fois à l’initialisation de la station blanche. Le remplacement de cette bi-clé
entrainera l’échec de la vérification de la signature de toutes les périphériques USB déjà signés. Par défaut, les clés privées
et publiques sont enregistrées dans /etc/keysas/. Il est important de sauvegarder ces clés dans un endroit sécurisé.
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
