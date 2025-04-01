import burp.*;

public class BurpUploadMain implements IBurpExtender, IIntruderPayloadGeneratorFactory {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Upload Auto Fuzz");

        callbacks.registerIntruderPayloadGeneratorFactory(this);

        callbacks.printOutput("loaded successfully - Author: e0e1 - Version: 1.0\ngithub: https://github.com/eeeeeeeeee-code/UploadFuzzBurp");
    }

    @Override
    public String getGeneratorName() {
        return "Upload Auto Fuzz";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new UploadFuzzer(this.helpers, attack, this.callbacks);
    }
}